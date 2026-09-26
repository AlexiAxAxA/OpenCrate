// SPDX-License-Identifier: MPL-2.0
//! Integrity tree over authenticated chunk frames.
//!
//! Leaves bind ciphertext as well as index, nonce, and tag: Poly1305 tags alone
//! are not collision-resistant for a holder of the payload key. Hashing ciphertext
//! also lets readers check the author-signed root before decrypting.
//!
//! Odd nodes are promoted, as in RFC 6962, rather than duplicated. The exposed root
//! binds the leaf count as well as the tree apex, so a proof cannot authenticate
//! a position in a differently sized tree. The mutable-region MAC separately
//! authenticates `total_len` and `chunk_count` for truncation checks.

use crate::{CryptoError, TreeHashAlg};

/// The hash this build actually uses to compute the tree.
///
/// Not a decorative constant: `leaf_of` and `node_of` below unconditionally hardcode
/// BLAKE3, and this is the sole declaration of what
/// `tree_hash_id` in the signed header must equal.
pub const IMPLEMENTED_TREE_HASH: TreeHashAlg = TreeHashAlg::Blake3;

/// Reject a tree algorithm this build does not implement.
///
/// The algorithm declared by the signed header must select the computation;
/// accepting SHA-256 while computing BLAKE3 would misinterpret that header.
pub fn ensure_supported(alg: TreeHashAlg) -> Result<(), CryptoError> {
    match alg {
        TreeHashAlg::Blake3 => Ok(()),
        // Идентификатор в реестре формата есть (docs/format.md §4), дерева на
        // нём в этой сборке нет.
        TreeHashAlg::Sha256 => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Tree leaf: a hash of chunk index, nonce, AEAD tag, and ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf(pub [u8; 32]);

/// Compute the leaf:
/// `H(0x00 ‖ "CC/v1/leaf" ‖ u32be(index) ‖ u64be(ct_len) ‖ nonce ‖ tag ‖ ct)`.
///
/// The prefix separates leaves from nodes. Ciphertext enters the hash because a
/// payload-key holder can construct Poly1305 tag collisions; tags alone cannot
/// bind content to the author-signed root. Hashing needs no key, so verification
/// can precede decryption. The explicit length fixes the ciphertext boundary.
/// [`ensure_supported`] selects the supported tree algorithm before this call.
pub fn leaf_of(index: u32, nonce: &[u8; 24], tag: &[u8; 16], ct: &[u8]) -> Leaf {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(crate::label::LEAF.as_bytes());
    h.update(&index.to_be_bytes());
    // `as u64` без проверки: на любой поддерживаемой платформе `usize` не шире
    // `u64`, поэтому преобразование не теряет ничего.
    h.update(&(ct.len() as u64).to_be_bytes());
    h.update(nonce);
    h.update(tag);
    h.update(ct);
    Leaf(*h.finalize().as_bytes())
}

/// Internal-node hash: `H(0x01 ‖ "CC/v1/node" ‖ left ‖ right)`.
pub fn node_of(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(crate::label::NODE.as_bytes());
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Root: `H(0x02 ‖ "CC/v1/node" ‖ u32be(leaf_count) ‖ apex)`.
///
/// `apex` follows RFC 6962. Binding leaf count prevents a proof from being reused
/// for a different tree size; prefix `0x02` separates roots from leaves and nodes.
pub fn root_of(leaf_count: u32, apex: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x02]);
    h.update(crate::label::NODE.as_bytes());
    h.update(&leaf_count.to_be_bytes());
    h.update(apex);
    *h.finalize().as_bytes()
}

/// Whether node `index` of a level of length `len` is promoted unchanged to the next level.
///
/// The sole declaration of the RFC 6962 rule. Construction, updating,
/// proof collection, and verification must see the same tree shape:
/// even one level of divergence would make proofs fail,
/// and only at particular chunk counts, meaning at a customer's site rather than in
/// a test.
fn is_promoted(len: usize, index: usize) -> bool {
    len % 2 == 1 && index.saturating_add(1) == len
}

/// Value of the parent of node `index` at level `level`.
///
/// A promoted node's parent equals itself; otherwise it is the hash of the pair
/// containing the node, whether the node is its left or right member.
fn parent_of(level: &[[u8; 32]], index: usize) -> Result<[u8; 32], CryptoError> {
    if is_promoted(level.len(), index) {
        return level.get(index).copied().ok_or(CryptoError::IndexOutOfRange);
    }
    let left_index = index.saturating_sub(index % 2);
    let right_index = left_index.saturating_add(1);
    let left = level.get(left_index).ok_or(CryptoError::IndexOutOfRange)?;
    let right = level.get(right_index).ok_or(CryptoError::IndexOutOfRange)?;
    Ok(node_of(left, right))
}

/// Entire tree in memory: 2n × 32 bytes, about 4 MiB for
/// a four-gigabyte file with 64 KiB chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a tree. An empty slice is invalid: every file has at least
    /// one chunk, even if zero-length.
    pub fn build(leaves: &[Leaf]) -> Result<Self, CryptoError> {
        if leaves.is_empty() {
            return Err(CryptoError::BadLength);
        }
        // Номер чанка входит в AAD как `u32be`, поэтому лист, который нельзя
        // назвать индексом u32, недостижим ни для чтения, ни для правки. Отказ
        // на построении честнее молчаливо непроверяемого хвоста.
        u32::try_from(leaves.len()).map_err(|_| CryptoError::BadLength)?;

        let mut current: Vec<[u8; 32]> = leaves.iter().map(|leaf| leaf.0).collect();
        // Уровней получается ceil(log2(n)) + 1, и после цикла верхний содержит
        // ровно один узел — на этом инварианте держится `root`.
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        while current.len() > 1 {
            let mut next: Vec<[u8; 32]> = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                match (pair.first(), pair.get(1)) {
                    (Some(left), Some(right)) => next.push(node_of(left, right)),
                    // Продвижение, а не `node_of(left, left)`: дублирование
                    // сделало бы корень набора [a, b, c] равным корню [a, b, c, c].
                    (Some(left), None) => next.push(*left),
                    (None, _) => {}
                }
            }
            levels.push(core::mem::replace(&mut current, next));
        }
        levels.push(current);
        Ok(Self { levels })
    }

    /// Tree apex: RFC 6962 `MTH`, without leaf-count binding.
    ///
    /// Externally (header, MAC, proof verification), [`root`] is used rather than
    /// the apex: differently shaped trees can share an apex, so a proof against it
    /// does not determine a leaf's position. It is exposed here because
    /// it is compared with the RFC 6962 reference implementation: promotion
    /// is checked independently from leaf-count binding.
    ///
    /// [`root`]: Self::root
    pub fn apex(&self) -> [u8; 32] {
        // Конструктор единственный и всегда оставляет верхний уровень из одного
        // узла, поэтому ветка с нулём недостижима. Паника в этом крейте
        // запрещена — запрет и существует ради таких «невозможных» случаев в
        // разборе враждебного ввода, — а нулевая вершина немедленно валит любую
        // проверку доказательства: тихо пройти она не может.
        self.levels.last().and_then(|top| top.first()).copied().unwrap_or([0u8; 32])
    }

    /// Root: apex bound to leaf count.
    pub fn root(&self) -> [u8; 32] {
        root_of(self.leaf_count(), &self.apex())
    }

    /// Leaf count.
    pub fn leaf_count(&self) -> u32 {
        // `build` уже отверг набор, не влезающий в u32, поэтому усечение
        // недостижимо.
        let count = self.levels.first().map_or(0, Vec::len);
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Replace a leaf and recompute the path to the root in O(log n). Returns the new
    /// root. This operation makes editing possible without rewriting
    /// the entire file.
    pub fn update_leaf(&mut self, index: u32, leaf: Leaf) -> Result<[u8; 32], CryptoError> {
        if index >= self.leaf_count() {
            return Err(CryptoError::IndexOutOfRange);
        }
        let mut position = usize::try_from(index).map_err(|_| CryptoError::IndexOutOfRange)?;
        // Проверка индекса сделана до записи: иначе неудачная правка оставила бы
        // дерево, не соответствующее ни одному набору чанков.
        *self
            .levels
            .first_mut()
            .and_then(|bottom| bottom.get_mut(position))
            .ok_or(CryptoError::IndexOutOfRange)? = leaf.0;

        // Поднимаемся ровно по одному узлу на уровень. Полное перестроение дало
        // бы тот же корень, но стоило бы O(n) хеширований на каждое сохранение
        // из приложения — а Word переписывает файл по нескольку раз в минуту.
        let mut depth = 0usize;
        loop {
            let level = self.levels.get(depth).ok_or(CryptoError::IndexOutOfRange)?;
            if level.len() <= 1 {
                break;
            }
            let parent = parent_of(level, position)?;
            let parent_position = position / 2;
            let above = depth.saturating_add(1);
            *self
                .levels
                .get_mut(above)
                .and_then(|upper| upper.get_mut(parent_position))
                .ok_or(CryptoError::TreeMismatch)? = parent;
            position = parent_position;
            depth = above;
        }
        Ok(self.root())
    }

    /// Proof path for a leaf.
    pub fn proof(&self, index: u32) -> Result<Vec<[u8; 32]>, CryptoError> {
        if index >= self.leaf_count() {
            return Err(CryptoError::IndexOutOfRange);
        }
        let mut position = usize::try_from(index).map_err(|_| CryptoError::IndexOutOfRange)?;
        let mut path = Vec::with_capacity(self.levels.len());
        for level in &self.levels {
            if level.len() <= 1 {
                break;
            }
            // У продвинутого узла соседа нет, и в путь ничего не кладётся.
            // Проверяющий выводит эти пропуски из `leaf_count`; форму дерева
            // задаёт не длина пути и не его содержимое, а `leaf_count` под
            // хешем корня — см. `root_of`.
            if !is_promoted(level.len(), position) {
                let sibling = if position % 2 == 0 {
                    position.saturating_add(1)
                } else {
                    position.saturating_sub(1)
                };
                path.push(*level.get(sibling).ok_or(CryptoError::TreeMismatch)?);
            }
            position /= 2;
        }
        Ok(path)
    }

    /// Verify a proof without building the tree. An associated function:
    /// the verifier does not need the entire tree.
    ///
    /// Success states exactly this: `leaf` occupies `index` in
    /// a `leaf_count`-leaf tree with this root. Neither index nor leaf count
    /// can be substituted: index determines concatenation sides, leaf count enters
    /// the root hash.
    pub fn verify_proof(
        root: &[u8; 32],
        index: u32,
        leaf_count: u32,
        leaf: &Leaf,
        proof: &[[u8; 32]],
    ) -> bool {
        if leaf_count == 0 || index >= leaf_count {
            return false;
        }
        let (Ok(mut len), Ok(mut position)) = (usize::try_from(leaf_count), usize::try_from(index))
        else {
            return false;
        };

        let mut accumulator = leaf.0;
        let mut used = 0usize;
        while len > 1 {
            if !is_promoted(len, position) {
                let Some(sibling) = proof.get(used) else {
                    return false;
                };
                used = used.saturating_add(1);
                // Сторона важна: `node_of` некоммутативен, иначе перестановка
                // соседей давала бы вторую последовательность листьев с тем же
                // корнем.
                accumulator = if position % 2 == 0 {
                    node_of(&accumulator, sibling)
                } else {
                    node_of(sibling, &accumulator)
                };
            }
            position /= 2;
            len = len.div_ceil(2);
        }
        // Непотраченный хвост — отказ. Иначе к подлинному пути дописывался бы
        // произвольный мусор, и доказательство перестало бы однозначно
        // соответствовать одному листу.
        if used != proof.len() {
            return false;
        }
        // Накопленное — это ВЕРШИНА, а не корень. Число листьев добавляется тем
        // же `root_of`, что и при построении: сравнивать вершину с корнем
        // напрямую значило бы вернуть ровно ту неоднозначность, ради устранения
        // которой связка с `leaf_count` и заведена — один и тот же путь подошёл
        // бы к дереву другого размера.
        let candidate = root_of(leaf_count, &accumulator);

        // Корень публичен, и утечка времени здесь ничего не даёт, но сравнение
        // хешей во всём репозитории делается одним способом — чтобы не
        // приходилось каждый раз доказывать, что именно тут ранний выход
        // безопасен. См. [`crate::digest_eq`].
        crate::digest_eq(&candidate, root)
    }

    /// Consistency proof (RFC 9162, §2.1.4.1): the tree over the first
    /// `old_count` leaves is a prefix of this tree.
    ///
    /// Needed by the log witness (D3): it stores only an old head, not entries;
    /// without such a proof, only someone holding the full log could verify
    /// "the new head extends the old one".
    ///
    /// One difference from the RFC follows from [`root_of`]: the verifier knows
    /// ROOTS rather than apexes. The RFC omits the old tree's apex when
    /// `old_count` is a power of two, since the verifier can supply it. Here
    /// there is nothing to supply, so it is placed at the path's start and is not
    /// taken on trust: verification maps it through `root_of` to the
    /// old head's root.
    ///
    /// # Errors
    /// [`CryptoError::IndexOutOfRange`]: `old_count` is zero or exceeds the tree size.
    pub fn consistency(&self, old_count: u32) -> Result<Vec<[u8; 32]>, CryptoError> {
        let leaves = self.levels.first().ok_or(CryptoError::TreeMismatch)?;
        let m = usize::try_from(old_count).map_err(|_| CryptoError::IndexOutOfRange)?;
        if m == 0 || m > leaves.len() {
            return Err(CryptoError::IndexOutOfRange);
        }
        let mut path = Vec::new();
        if m == leaves.len() {
            return Ok(path);
        }
        if m.is_power_of_two() {
            let prefix = leaves.get(..m).ok_or(CryptoError::IndexOutOfRange)?;
            path.push(mth(prefix).ok_or(CryptoError::TreeMismatch)?);
        }
        subproof(m, leaves, true, &mut path).ok_or(CryptoError::TreeMismatch)?;
        Ok(path)
    }

    /// Verify a consistency proof without the tree (RFC 9162,
    /// §2.1.4.2, with the difference described in [`Self::consistency`]).
    ///
    /// Success means the `old_count`-leaf tree with root `old_root` is
    /// a prefix of the `new_count`-leaf tree with root `new_root`. Equal sizes
    /// are consistent only with equal roots and an empty path; a smaller new size
    /// is never consistent, because the log is append-only.
    pub fn verify_consistency(
        old_count: u32,
        old_root: &[u8; 32],
        new_count: u32,
        new_root: &[u8; 32],
        proof: &[[u8; 32]],
    ) -> bool {
        if old_count == 0 || old_count > new_count {
            return false;
        }
        if old_count == new_count {
            return proof.is_empty() && crate::digest_eq(old_root, new_root);
        }
        let Some((first, rest)) = proof.split_first() else {
            return false;
        };
        let (Some(mut fnode), Some(mut snode)) = (old_count.checked_sub(1), new_count.checked_sub(1)) else {
            return false;
        };
        // Общий правый край старого и нового деревьев доказательству не нужен:
        // снимаем уровни, пока старый узел — правый потомок.
        while fnode % 2 == 1 {
            fnode /= 2;
            snode /= 2;
        }
        let mut old_acc = *first;
        let mut new_acc = *first;
        for sibling in rest {
            if snode == 0 {
                return false;
            }
            if fnode % 2 == 1 || fnode == snode {
                // Левый сосед: он общий у обоих деревьев.
                old_acc = node_of(sibling, &old_acc);
                new_acc = node_of(sibling, &new_acc);
                while fnode % 2 == 0 && fnode != 0 {
                    fnode /= 2;
                    snode /= 2;
                }
            } else {
                // Правый сосед: его в старом дереве ещё не было.
                new_acc = node_of(&new_acc, sibling);
            }
            fnode /= 2;
            snode /= 2;
        }
        // Оба сравнения выполняются всегда: ранний выход ничего не выдал бы
        // (корни публичны), но доктрина сравнения одна на репозиторий.
        let old_ok = crate::digest_eq(&root_of(old_count, &old_acc), old_root);
        let new_ok = crate::digest_eq(&root_of(new_count, &new_acc), new_root);
        snode == 0 && old_ok && new_ok
    }
}

/// Largest power of two strictly below `n` (RFC 6962, §2.1). Called with
/// `n ≥ 2`.
fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

/// `MTH` over a leaf slice, split at the largest power of two, as in
/// RFC 6962.
///
/// Matches the apex of [`MerkleTree`] of the same size: bottom-up construction
/// with odd-node promotion and top-down splitting produce the same tree
/// (probe `the_recursive_mth_is_the_apex_of_the_level_tree`).
fn mth(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    match leaves {
        [] => None,
        [only] => Some(*only),
        _ => {
            let (left, right) = leaves.split_at_checked(split_point(leaves.len()))?;
            Some(node_of(&mth(left)?, &mth(right)?))
        }
    }
}

/// `SUBPROOF` from RFC 9162, §2.1.4.1. `complete` means the old tree exactly matches
/// the current subtree (so the verifier already has its apex).
fn subproof(m: usize, leaves: &[[u8; 32]], complete: bool, out: &mut Vec<[u8; 32]>) -> Option<()> {
    if m == leaves.len() {
        if !complete {
            out.push(mth(leaves)?);
        }
        return Some(());
    }
    let k = split_point(leaves.len());
    let (left, right) = leaves.split_at_checked(k)?;
    if m <= k {
        subproof(m, left, complete, out)?;
        out.push(mth(right)?);
    } else {
        subproof(m.checked_sub(k)?, right, false, out)?;
        out.push(mth(left)?);
    }
    Some(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Required sizes: 1 is degenerate, 2 and 8 are full powers
    /// of two, 3 and 5 require one promotion, 100 requires promotions at several
    /// levels (100 → 50 → 25 → 13 → 7 → 4 → 2 → 1).
    const SIZES: [u32; 6] = [1, 2, 3, 5, 8, 100];

    /// A leaf deterministically derived from its index: tests must be
    /// reproducible, leaves pairwise distinct.
    fn test_leaf(index: u32) -> Leaf {
        let seed = *blake3::hash(&index.to_be_bytes()).as_bytes();
        let mut nonce = [0u8; 24];
        let mut tag = [0u8; 16];
        for (dst, src) in nonce.iter_mut().zip(seed.iter()) {
            *dst = *src;
        }
        for (dst, src) in tag.iter_mut().zip(seed.iter().rev()) {
            *dst = *src;
        }
        // Шифротекст тоже выводится из семени: лист обязан зависеть от него, и
        // тесты формы дерева должны считать лист так же, как продукт.
        leaf_of(index, &nonce, &tag, &seed)
    }

    fn test_leaves(count: u32) -> Vec<Leaf> {
        (0..count).map(test_leaf).collect()
    }

    fn at(leaves: &[Leaf], index: u32) -> Leaf {
        leaves.get(usize::try_from(index).unwrap()).copied().unwrap()
    }

    /// A leaf with one flipped bit: exactly what an adversary does by substituting
    /// chunk contents without changing file length.
    fn corrupt(leaf: Leaf) -> Leaf {
        let mut bytes = leaf.0;
        if let Some(first) = bytes.first_mut() {
            *first ^= 0x01;
        }
        Leaf(bytes)
    }

    /// Sequence of "promoted / not promoted" by level: path shape from
    /// leaf to root. Depends on both index and leaf count.
    fn promotion_pattern(count: u32, index: u32) -> Vec<bool> {
        let mut pattern = Vec::new();
        let mut len = usize::try_from(count).unwrap();
        let mut position = usize::try_from(index).unwrap();
        while len > 1 {
            pattern.push(is_promoted(len, position));
            position /= 2;
            len = len.div_ceil(2);
        }
        pattern
    }

    #[test]
    fn the_only_honoured_tree_hash_is_the_one_the_hasher_computes() {
        // Объявленный алгоритм обязан управлять решением, а не украшать
        // заголовок. Лист считается BLAKE3 безусловно — значит принят может быть
        // ровно BLAKE3, а любой другой член реестра обязан отвергаться до того,
        // как хоть один байт дерева будет посчитан.
        assert_eq!(IMPLEMENTED_TREE_HASH, TreeHashAlg::Blake3);
        assert_eq!(ensure_supported(TreeHashAlg::Blake3), Ok(()));
        assert_eq!(
            ensure_supported(TreeHashAlg::Sha256),
            Err(CryptoError::UnsupportedAlgorithm),
            "сборка соглашается на хеш дерева, которого не умеет считать"
        );
    }

    #[test]
    fn a_tree_hash_identifier_this_build_cannot_compute_is_refused_at_parse_time() {
        // Разбор идентификатора и способность его исполнить обязаны совпадать:
        // разойдись они — файл со SHA-256 в suite прошёл бы разбор и был бы
        // прочитан по BLAKE3.
        assert_eq!(TreeHashAlg::from_u8(1), Ok(TreeHashAlg::Blake3));
        assert_eq!(TreeHashAlg::from_u8(2), Err(CryptoError::UnsupportedAlgorithm));
        for v in [0u8, 3, 99, 255] {
            assert_eq!(TreeHashAlg::from_u8(v), Err(CryptoError::UnsupportedAlgorithm));
        }
    }

    #[test]
    fn an_empty_leaf_set_is_rejected() {
        // У любого файла есть хотя бы один чанк, пусть и нулевой длины. Дерево
        // без листьев означало бы корень, которому нечему соответствовать.
        assert_eq!(MerkleTree::build(&[]), Err(CryptoError::BadLength));
    }

    #[test]
    fn a_single_leaf_tree_binds_its_root_to_the_leaf_count() {
        // Раньше корень дерева из одного листа РАВНЯЛСЯ этому листу, и тест так и
        // назывался. Равенство пришлось убрать: корень, совпадающий с вершиной,
        // не различает деревья разного размера, и одно доказательство подходило
        // сразу к нескольким парам (индекс, число листьев). Теперь число листьев
        // входит в хеш корня, и вершина корнем уже не является.
        let leaf = test_leaf(0);
        let tree = MerkleTree::build(&[leaf]).unwrap();
        assert_eq!(tree.root(), root_of(1, &leaf.0));
        assert_ne!(tree.root(), leaf.0, "корень обязан отличаться от вершины");
        assert_eq!(tree.leaf_count(), 1);
        assert!(tree.proof(0).unwrap().is_empty());
        assert!(MerkleTree::verify_proof(&tree.root(), 0, 1, &leaf, &[]));
    }

    #[test]
    fn the_root_of_three_leaves_follows_rfc6962_promotion() {
        // Форма зафиксирована явно: подмени кто-нибудь продвижение
        // дублированием — сломается именно это равенство, а не абстрактное
        // «что-то в дереве».
        let leaves = test_leaves(3);
        let apex = node_of(&node_of(&at(&leaves, 0).0, &at(&leaves, 1).0), &at(&leaves, 2).0);
        // Вершина по RFC 6962, поверх неё — связка с числом листьев.
        assert_eq!(MerkleTree::build(&leaves).unwrap().root(), root_of(3, &apex));
    }

    #[test]
    fn every_leaf_proof_verifies_and_a_corrupted_leaf_does_not() {
        for count in SIZES {
            let leaves = test_leaves(count);
            let tree = MerkleTree::build(&leaves).unwrap();
            assert_eq!(tree.leaf_count(), count);
            let root = tree.root();
            for index in 0..count {
                let leaf = at(&leaves, index);
                let proof = tree.proof(index).unwrap();
                assert!(
                    MerkleTree::verify_proof(&root, index, count, &leaf, &proof),
                    "лист {index} из {count} не подтверждается собственным доказательством"
                );
                assert!(
                    !MerkleTree::verify_proof(&root, index, count, &corrupt(leaf), &proof),
                    "изменённый лист {index} из {count} принят как подлинный"
                );
            }
        }
    }

    #[test]
    fn an_incremental_update_equals_a_full_rebuild() {
        // Смысл `update_leaf` — то же самое дерево за O(log n). Сравниваем не
        // только корень, но и все уровни: расхождение в середине проявилось бы
        // позже и в другом месте — на доказательстве соседнего листа.
        for count in SIZES {
            let leaves = test_leaves(count);
            for index in 0..count {
                let mut tree = MerkleTree::build(&leaves).unwrap();
                let replacement = test_leaf(index.saturating_add(1_000_000));
                let new_root = tree.update_leaf(index, replacement).unwrap();

                let mut edited = leaves.clone();
                *edited.get_mut(usize::try_from(index).unwrap()).unwrap() = replacement;
                let rebuilt = MerkleTree::build(&edited).unwrap();

                assert_eq!(new_root, rebuilt.root(), "корень после правки {index} из {count}");
                assert_eq!(tree, rebuilt, "уровни после правки {index} из {count}");
                assert!(MerkleTree::verify_proof(
                    &new_root,
                    index,
                    count,
                    &replacement,
                    &tree.proof(index).unwrap()
                ));
            }
        }
    }

    #[test]
    fn three_leaves_and_four_leaves_with_a_repeated_tail_have_different_roots() {
        // Ровно CVE-2012-2459: при дублировании последнего узла вместо
        // продвижения [a, b, c] и [a, b, c, c] дали бы один корень, и файл с
        // лишним чанком выдавался бы за исходный.
        let three = test_leaves(3);
        let mut four = three.clone();
        four.push(at(&three, 2));

        let root_three = MerkleTree::build(&three).unwrap().root();
        let root_four = MerkleTree::build(&four).unwrap().root();
        assert_ne!(root_three, root_four, "продвижение подменено дублированием");

        let left = node_of(&at(&three, 0).0, &at(&three, 1).0);
        let right = node_of(&at(&three, 2).0, &at(&three, 2).0);
        assert_eq!(root_four, root_of(4, &node_of(&left, &right)));
    }

    #[test]
    fn distinct_leaf_sets_produce_distinct_roots() {
        let base = test_leaves(8);
        let mut sets: Vec<Vec<Leaf>> = (1..=8)
            .map(|len| base.iter().copied().take(len).collect::<Vec<Leaf>>())
            .collect();
        // Хвост-дубликат, перестановка и повтор одного листа — три способа
        // получить столкновение в наивной реализации.
        let mut repeated_tail = base.iter().copied().take(3).collect::<Vec<Leaf>>();
        repeated_tail.push(at(&base, 2));
        sets.push(repeated_tail);
        sets.push(vec![at(&base, 1), at(&base, 0)]);
        sets.push(vec![at(&base, 0), at(&base, 0)]);

        let roots: BTreeSet<[u8; 32]> =
            sets.iter().map(|set| MerkleTree::build(set).unwrap().root()).collect();
        assert_eq!(roots.len(), sets.len(), "разные наборы листьев дали одинаковый корень");
    }

    #[test]
    fn a_proof_does_not_verify_at_another_index() {
        // Иначе доказательство было бы переносимым: чанк, честно прочитанный по
        // одному смещению, выдавался бы за содержимое другого.
        for count in [2u32, 3, 5, 8] {
            let leaves = test_leaves(count);
            let tree = MerkleTree::build(&leaves).unwrap();
            let root = tree.root();
            for index in 0..count {
                let leaf = at(&leaves, index);
                let proof = tree.proof(index).unwrap();
                for other in (0..count).filter(|other| *other != index) {
                    assert!(
                        !MerkleTree::verify_proof(&root, other, count, &leaf, &proof),
                        "доказательство листа {index} прошло как доказательство {other} из {count}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_proof_does_not_verify_under_a_leaf_count_that_changes_the_shape() {
        // `leaf_count` — не только граница индекса: из него проверяющий выводит,
        // на каких уровнях узел продвигался. Соврав про число листьев, противник
        // меняет форму пути, и накопленный хеш перестаёт сходиться с корнем.
        //
        // Оговорка, которую нельзя замалчивать: свойство верно ТОЛЬКО там, где
        // форма пути действительно меняется. Для листа 0 деревья из 7 и 8
        // листьев неотличимы — на всём пути влево продвижений нет ни там, ни
        // там, — и одно и то же доказательство проходит при обоих значениях.
        // Информации, которая их различила бы, во входных данных просто нет.
        // Настоящую границу файла задаёт `chunk_count` под MAC изменяемой
        // области (§6.4 спецификации), а не дерево.
        let mut checked = 0u32;
        for count in [2u32, 3, 5, 8, 100] {
            let leaves = test_leaves(count);
            let tree = MerkleTree::build(&leaves).unwrap();
            let root = tree.root();
            for index in [0, count / 2, count.saturating_sub(1)] {
                let leaf = at(&leaves, index);
                let proof = tree.proof(index).unwrap();
                for wrong in 1..=count.saturating_add(2) {
                    if wrong <= index
                        || promotion_pattern(wrong, index) == promotion_pattern(count, index)
                    {
                        continue;
                    }
                    checked = checked.saturating_add(1);
                    assert!(
                        !MerkleTree::verify_proof(&root, index, wrong, &leaf, &proof),
                        "доказательство листа {index} прошло при leaf_count {wrong} вместо {count}"
                    );
                }
            }
        }
        // Страховка от вырождения: тест обязан был хоть что-то проверить.
        assert!(checked > 0, "ни одного различимого leaf_count не нашлось");
    }

    #[test]
    fn a_proof_of_the_wrong_length_is_refused() {
        // Непотраченный хвост и недостача обязаны отвергаться: иначе к
        // подлинному пути дописывается что угодно, и оно продолжает проходить.
        let leaves = test_leaves(5);
        let tree = MerkleTree::build(&leaves).unwrap();
        let leaf = at(&leaves, 1);

        let mut longer = tree.proof(1).unwrap();
        longer.push([0x42; 32]);
        assert!(!MerkleTree::verify_proof(&tree.root(), 1, 5, &leaf, &longer));

        let mut shorter = tree.proof(1).unwrap();
        shorter.pop();
        assert!(!MerkleTree::verify_proof(&tree.root(), 1, 5, &leaf, &shorter));
    }

    #[test]
    fn an_index_outside_the_tree_is_refused() {
        let leaves = test_leaves(5);
        let mut tree = MerkleTree::build(&leaves).unwrap();
        assert_eq!(tree.proof(5), Err(CryptoError::IndexOutOfRange));
        assert_eq!(tree.proof(u32::MAX), Err(CryptoError::IndexOutOfRange));
        assert_eq!(tree.update_leaf(5, test_leaf(0)), Err(CryptoError::IndexOutOfRange));
        // Проверяющая сторона дерева не имеет и обязана отказать сама.
        assert!(!MerkleTree::verify_proof(&tree.root(), 5, 5, &at(&leaves, 0), &[]));
        assert!(!MerkleTree::verify_proof(&tree.root(), 0, 0, &at(&leaves, 0), &[]));
    }

    #[test]
    fn a_failed_update_leaves_the_tree_untouched() {
        // Отказ по индексу происходит до записи листа: полуприменённая правка
        // оставила бы дерево, не соответствующее ни одному набору чанков.
        let leaves = test_leaves(5);
        let mut tree = MerkleTree::build(&leaves).unwrap();
        let before = tree.clone();
        assert!(tree.update_leaf(99, test_leaf(7)).is_err());
        assert_eq!(tree, before);
    }

    fn raw(leaves: &[Leaf]) -> Vec<[u8; 32]> {
        leaves.iter().map(|l| l.0).collect()
    }

    #[test]
    fn the_recursive_mth_is_the_apex_of_the_level_tree() {
        for n in 1..=70u32 {
            let leaves = test_leaves(n);
            let tree = MerkleTree::build(&leaves).unwrap();
            assert_eq!(mth(&raw(&leaves)), Some(tree.apex()), "n = {n}");
        }
    }

    /// Every size pair through 40: the proof verifies ONLY
    /// with the correct roots and sizes.
    #[test]
    fn every_prefix_is_proven_consistent_and_nothing_else_is() {
        let all = test_leaves(40);
        for new in 1..=40u32 {
            let tree = MerkleTree::build(&all[..new as usize]).unwrap();
            for old in 1..=new {
                let old_root = MerkleTree::build(&all[..old as usize]).unwrap().root();
                let proof = tree.consistency(old).unwrap();
                assert!(
                    MerkleTree::verify_consistency(old, &old_root, new, &tree.root(), &proof),
                    "{old} → {new} не сошлось"
                );
                if old == new {
                    assert!(proof.is_empty());
                    continue;
                }
                // Чужой старый корень, чужой новый, чужие размеры.
                let mut bad = old_root;
                bad[0] ^= 1;
                assert!(!MerkleTree::verify_consistency(old, &bad, new, &tree.root(), &proof));
                assert!(!MerkleTree::verify_consistency(old, &old_root, new, &bad, &proof));
                if old > 1 {
                    assert!(!MerkleTree::verify_consistency(old - 1, &old_root, new, &tree.root(), &proof));
                }
                assert!(!MerkleTree::verify_consistency(old, &old_root, new + 1, &tree.root(), &proof));
                // Порча любого узла пути, укороченный и удлинённый путь.
                for i in 0..proof.len() {
                    let mut p = proof.clone();
                    p[i][31] ^= 0x80;
                    assert!(
                        !MerkleTree::verify_consistency(old, &old_root, new, &tree.root(), &p),
                        "{old} → {new}: порча узла {i} прошла"
                    );
                }
                let mut shorter = proof.clone();
                shorter.pop();
                assert!(!MerkleTree::verify_consistency(old, &old_root, new, &tree.root(), &shorter));
                let mut longer = proof.clone();
                longer.push([7; 32]);
                assert!(!MerkleTree::verify_consistency(old, &old_root, new, &tree.root(), &longer));
            }
        }
    }

    /// Fork: identical prefix length, different history; neither tree
    /// provides a valid proof.
    #[test]
    fn a_forked_history_is_not_consistent() {
        let honest = test_leaves(9);
        let mut forked = honest.clone();
        forked[2] = corrupt(forked[2]);
        let old_root = MerkleTree::build(&honest[..5]).unwrap().root();
        let fork_tree = MerkleTree::build(&forked).unwrap();
        let proof = fork_tree.consistency(5).unwrap();
        assert!(!MerkleTree::verify_consistency(5, &old_root, 9, &fork_tree.root(), &proof));
        // Откат: меньший новый размер не согласован никогда.
        let big = MerkleTree::build(&honest).unwrap();
        assert!(!MerkleTree::verify_consistency(9, &big.root(), 5, &old_root, &[]));
        assert_eq!(big.consistency(0), Err(CryptoError::IndexOutOfRange));
        assert_eq!(big.consistency(10), Err(CryptoError::IndexOutOfRange));
    }
}
