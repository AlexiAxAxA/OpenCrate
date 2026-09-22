// Проба скептика: перепроверка заявления «внутри слота ключа неизвестный тег из
// критичного диапазона молча отбрасывается». Прежняя проба брала тег 7, который
// у слота ЗАНЯТ (nonce), и получала отказ по длине значения — то есть проверяла
// не то, что заявляла. Здесь берётся тег, действительно неизвестный слоту.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assertions_on_constants
)]

use oc_crypto::{AeadAlg, KemAlg, SigAlg, TreeHashAlg};
use oc_format::header::{
    Authority, CONTAINER_VERSION, Header, KeySlot, KnownSlot, SUPPORTED_READER_VERSION, SlotKind,
    Suite, WRAPPED_CEK_LEN, tag as htag,
};
use oc_format::FormatError;
use oc_format::tlv::{CRIT_TAG_MAX, TlvReader, TlvWriter};
use oc_policy::Policy;

fn sample_header() -> Header {
    sample_header_at(CONTAINER_VERSION)
}

/// Заголовок с ЯВНО заданной версией контейнера.
///
/// Нужен потому, что форма полей слота — функция пары (версия, механизм), и
/// проверки про «форму этой версии» обязаны называть версию сами, а не наследовать
/// её от константы записи. Константа поднимется на последнем этапе перехода и
/// утащила бы за собой смысл тестов, которые про версию 1.
fn sample_header_at(container_version: u16) -> Header {
    Header {
        container_version,
        min_reader_version: SUPPORTED_READER_VERSION,
        file_id: [0x11; 16],
        suite: Suite {
            sig: SigAlg::Ed25519,
            aead: AeadAlg::XChaCha20Poly1305,
            tree_hash: TreeHashAlg::Blake3,
        },
        author_key: [0x01; 32],
        header_salt: [0x22; 32],
        chunk_size: 65536,
        original_root: [0x33; 32],
        policy: Policy::deny_all(),
        key_slots: vec![KeySlot::Known(KnownSlot {
            kind: SlotKind::AuthorDevice,
            kem: KemAlg::X25519HkdfSha256,
            enc: vec![0x44; 32],
            nonce: [0x01; 24],
            ct: vec![0x55; 48],
            commitment: [0x66; 32],
            key_fpr: Some(vec![0x77; 32]),
            claim_commit: None,
        })],
        authority: Authority {
            urls: Vec::new(),
            sealing_kid: [0x88; 32],
            lease_verify_key: [0x99; 32],
        },
        private_meta: vec![0xaa; 64],
        prev_header_hash: None,
        org_id: b"org".to_vec(),
        class: 0,
        footer_offset: None,
        wrapped_cek: [0xbb; WRAPPED_CEK_LEN],
        coauthors: None,
    }
}

fn replace_field(header_bytes: &[u8], tag: u16, new_value: &[u8]) -> Vec<u8> {
    let mut reader = TlvReader::new(header_bytes);
    let mut w = TlvWriter::new();
    while let Some(field) = reader.next_field().unwrap() {
        if field.tag == tag {
            w.put(field.tag, new_value).unwrap();
        } else {
            w.put(field.tag, field.value).unwrap();
        }
    }
    w.finish().to_vec()
}

#[test]
fn an_unknown_critical_tag_inside_a_key_slot_is_not_dropped_in_silence() {
    // Теги слота из docs/format.md §3.3. Берётся ВЕРХНЯЯ граница критичного
    // диапазона, а не первый свободный номер: реестр растёт снизу, и «первый
    // свободный» уже дважды успевал стать занятым (тег 7 → NONCE, тег 8 →
    // CLAIM_COMMIT). Проба при этом продолжала проходить, проверяя вместо
    // диапазона тега длину известного поля.
    const UNKNOWN_CRITICAL: u16 = CRIT_TAG_MAX;

    let mut slot = TlvWriter::new();
    slot.put(1, &(SlotKind::AuthorDevice as u16).to_le_bytes()).unwrap();
    slot.put(2, &[KemAlg::X25519HkdfSha256 as u8]).unwrap();
    slot.put(3, &[0x44; 32]).unwrap();
    slot.put(4, &[0x55; 48]).unwrap();
    slot.put(5, &[0x66; 32]).unwrap();
    slot.put(6, &[0x77; 32]).unwrap();
    slot.put(7, &[0x01; 24]).unwrap();
    slot.put(UNKNOWN_CRITICAL, b"a constraint from a future version").unwrap();

    let mut slots = TlvWriter::new();
    slots.put(0, &slot.finish()).unwrap();
    let header =
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish());

    match Header::decode(&header) {
        // Отказ — корректная реакция по §2.
        Err(_) => {}
        Ok(parsed) => {
            assert!(
                !matches!(parsed.header.key_slots.first(), Some(KeySlot::Known(_))),
                "слот с неизвестным критичным полем {UNKNOWN_CRITICAL} отдан как пригодный: \
                 ограничение из будущей версии потеряно молча"
            );
        }
    }
}

/// Слот на механизме, форму которого версия 1 не задаёт, обязан пропускаться — а не
/// отвергать весь контейнер.
///
/// Это пункт Р-3, и он про обещание §3.3: «слот со знакомым видом, но незнакомым
/// `kem_id`, пропускается, а не отвергает файл». Выполнить его было нельзя в
/// принципе, и причина тонкая. Ветка-спасатель «незнакомый механизм → `Unknown`»
/// стояла ПОСЛЕ цикла разбора полей, а длина `enc` проверялась ВНУТРИ цикла и
/// безусловно требовала 32 байта — то есть до спасателя дело не доходило. Хуже
/// того, ветка была недостижима и вторым способом: `KemAlg::from_u8` считает 2 и 3
/// знакомыми, так что для P-256 «незнакомый механизм» не наступал вовсе.
///
/// Публичный ключ P-256 занимает 33 или 65 байт, и ни одна из этих форм в 32 байта
/// не влезает. Значит слот на P-256 был не «незнакомым», а **невозможным**: любой
/// такой контейнер отвергался целиком, даже когда рядом лежал наш собственный,
/// полностью открываемый слот. Ф-6 планировал именно P-256 через TPM.
///
/// ## Этот тест обязан сломаться, и чинить его надо не так, как хочется
///
/// Он держится на том, что форма P-256 версии 1 НЕ ЗАДАНА. Ф-6 её задаёт: спайк
/// `spikes/tpm-ecdh` показал, что PCP отдаёт публичный ключ только несжатым, то есть
/// на провод пойдёт `0x04 ‖ X ‖ Y` — ровно те 65 байт, что построены ниже. С этого
/// момента слот перестанет быть `Unknown` и станет разбираемым, и тест упадёт.
///
/// Падение будет ПРАВИЛЬНЫМ, а очевидная починка — нет. Поменять ожидание на
/// `Known` значит превратить проверку Р-3 в проверку того, что P-256 работает;
/// ветка «незнакомый механизм пропускается, а не рушит файл» перестанет проверяться
/// вовсе, и следующая регрессия того же рода пройдёт молча.
///
/// ## Как это разрешилось на самом деле
///
/// Предписание выше — «перенести на `kem_id = 3`» — было верным для мира, где форма
/// зависит только от механизма. Версия 2 сделала её функцией ПАРЫ (версия,
/// механизм), и это открыло вариант лучше: проверить оба утверждения, а не одно
/// вместо другого.
///
/// Этот тест остаётся про P-256 и прибивается к **версии 1**, где его форма не
/// задана и задана не будет никогда: заморожено не только то, что версия умеет, но
/// и то, чего она не умеет. Утверждение Р-3 сохраняется дословно и получает вторым
/// смыслом защиту от того, чтобы версия 1 задним числом обрела семантику.
///
/// Ветку же «механизм, форму которого не задаёт НИ ОДНА версия» стережёт соседний
/// тест на `kem_id = 3` в контейнере версии 2 — там, где P-256 уже разбирается.
/// Вместе они покрывают то, что поодиночке покрывалось бы через раз.
#[test]
fn a_slot_whose_kem_shape_this_version_does_not_define_is_skipped_not_fatal() {
    // Два слота: чужой (P-256 с 65-байтным `enc`) и наш. Контейнер версии 1.
    let mut foreign = TlvWriter::new();
    foreign.put(1, &(SlotKind::RecipientIdentity as u16).to_le_bytes()).unwrap();
    foreign.put(2, &[KemAlg::P256HkdfSha256 as u8]).unwrap();
    // Несжатая точка P-256: 0x04 ‖ X(32) ‖ Y(32).
    let mut p256 = vec![0x04u8];
    p256.extend_from_slice(&[0xab; 64]);
    foreign.put(3, &p256).unwrap();
    foreign.put(4, &[0x55; 48]).unwrap();
    foreign.put(5, &[0x66; 32]).unwrap();
    foreign.put(6, &p256).unwrap();
    foreign.put(7, &[0x01; 24]).unwrap();

    let ours = sample_header_at(1).key_slots;
    let ours_encoded = {
        let mut only_ours = sample_header_at(1);
        only_ours.key_slots = ours.clone();
        // Кодируем наш слот тем же путём, которым его пишет продукт, и вынимаем
        // готовую запись: собирать её здесь руками значило бы проверять свою же
        // сборку вместо продуктовой.
        let bytes = only_ours.encode().unwrap();
        let mut reader = TlvReader::new(&bytes);
        let mut found = None;
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag == htag::KEY_SLOTS {
                let mut inner = TlvReader::new(field.value);
                if let Some(slot) = inner.next_field().unwrap() {
                    found = Some(slot.value.to_vec());
                }
            }
        }
        found.expect("слот обязан быть в закодированном заголовке")
    };

    let mut slots = TlvWriter::new();
    slots.put(0, &foreign.finish()).unwrap();
    slots.put(1, &ours_encoded).unwrap();
    let header =
        replace_field(&sample_header_at(1).encode().unwrap(), htag::KEY_SLOTS, &slots.finish());

    let parsed = Header::decode(&header).expect(
        "контейнер отвергнут целиком из-за слота на чужом механизме: обещание §3.3 \
         «пропускается, а не отвергает файл» не выполняется",
    );

    assert!(
        matches!(parsed.header.key_slots.first(), Some(KeySlot::Unknown { .. })),
        "чужой слот разобран как пригодный: {:?}",
        parsed.header.key_slots.first()
    );
    assert!(
        matches!(parsed.header.key_slots.get(1), Some(KeySlot::Known(_))),
        "наш слот потерян: {:?}",
        parsed.header.key_slots.get(1)
    );

    // И-8 не ослаблен: для механизма, форму которого версия задаёт, длина
    // по-прежнему точная. 33 байта в `enc` при `kem_id = 1` — отказ, а не «сойдёт».
    let mut wrong = TlvWriter::new();
    wrong.put(1, &(SlotKind::AuthorDevice as u16).to_le_bytes()).unwrap();
    wrong.put(2, &[KemAlg::X25519HkdfSha256 as u8]).unwrap();
    wrong.put(3, &[0x44; 33]).unwrap();
    wrong.put(4, &[0x55; 48]).unwrap();
    wrong.put(5, &[0x66; 32]).unwrap();
    wrong.put(7, &[0x01; 24]).unwrap();
    let mut slots = TlvWriter::new();
    slots.put(0, &wrong.finish()).unwrap();
    let header =
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish());
    assert!(
        Header::decode(&header).is_err(),
        "33 байта в enc при X25519 приняты: точная длина известного механизма ослаблена"
    );
}

/// Слот кода-претензии не может нести байты, за которые никто не отвечает.
///
/// Пункт Р-4. §2.0 объявляет таблицу состава слота исполняемой **целиком**, а
/// исполнялись две трети: проверялись `ct` и `claim_commit`, но не `key_fpr` по виду
/// и не нулевые `enc`/`nonce`. Значит слот кода-претензии мог нести 32 байта
/// `key_fpr` и произвольные 56 байт в `enc` и `nonce`, пройти проверку и жить внутри
/// **подписанного автором** заголовка, не будучи прочитанным никем.
///
/// Это дословно тот аргумент, которым спека запрещает непустой `ct` в этом же слоте:
/// «байты, за которые никто не отвечает… место для скрытого канала внутри
/// подписанного автором заголовка». Запрет был выписан для одного поля из трёх.
#[test]
fn a_claim_slot_cannot_smuggle_bytes_in_fields_it_does_not_use() {
    let base = |enc: &[u8], nonce: &[u8], with_fpr: bool| {
        let mut slot = TlvWriter::new();
        slot.put(1, &(SlotKind::RecipientClaim as u16).to_le_bytes()).unwrap();
        slot.put(2, &[KemAlg::X25519HkdfSha256 as u8]).unwrap();
        slot.put(3, enc).unwrap();
        slot.put(4, &[]).unwrap();
        slot.put(5, &[0x66; 32]).unwrap();
        if with_fpr {
            slot.put(6, &[0x77; 32]).unwrap();
        }
        slot.put(7, nonce).unwrap();
        slot.put(8, &[0x99; 32]).unwrap();
        let mut slots = TlvWriter::new();
        slots.put(0, &slot.finish()).unwrap();
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish())
    };

    // Контроль: честный слот кода-претензии обязан разбираться. Без него зелёные
    // отказы ниже могли бы означать, что отвергается вообще всё.
    let honest = base(&[0u8; 32], &[0u8; 24], false);
    assert!(
        matches!(Header::decode(&honest).map(|p| p.header.key_slots), Ok(slots) if
            matches!(slots.first(), Some(KeySlot::Known(_)))),
        "честный слот кода-претензии отвергнут"
    );

    // Три канала контрабанды, каждый по отдельности.
    for (what, header) in [
        ("enc", base(&[0xab; 32], &[0u8; 24], false)),
        ("nonce", base(&[0u8; 32], &[0xcd; 24], false)),
        ("key_fpr", base(&[0u8; 32], &[0u8; 24], true)),
    ] {
        assert!(
            Header::decode(&header).is_err(),
            "слот кода-претензии с непустым {what} принят: подписанный автором \
             заголовок несёт байты, которых никто не читает"
        );
    }
}

/// Слот кода-претензии объявляет `kem_id = 1` — всегда, и это про БАЙТЫ.
///
/// §2 п.5 записан дословно: «Слот кода-претензии (`kind = 3`) объявляет
/// `kem_id = 1` **всегда**, а его нулевые `enc` и `nonce` имеют длину 32 и 24.
/// Без этой строки длина нулевого `enc` начала бы зависеть от несвязанного выбора
/// механизма по умолчанию, и байты `claim.cc` поехали бы молча».
///
/// Проверка этой строки отсутствовала, и отсутствие было НЕВИДИМЫМ: слот с
/// `kem_id = 2` несёт 65 нулей вместо 32, оба числа проходят проверку «все нули»,
/// обе длины законны каждая для своего механизма. То есть один и тот же
/// `claim.cc` мог быть выпущен в двух разных байтовых видах, и оба принимались.
/// Для формата, объявленного замороженным, это ровно то, чем §2 п.5 и пугает.
///
/// Хуже того, принимали обе стороны: писатель производил то, что читатель обязан
/// был отвергнуть. Нашла это опытная проба, а не разбор кода.
#[test]
fn a_claim_slot_must_declare_the_first_mechanism() {
    let claim_with = |kem: KemAlg, enc_len: usize| {
        let mut slot = TlvWriter::new();
        slot.put(1, &(SlotKind::RecipientClaim as u16).to_le_bytes()).unwrap();
        slot.put(2, &[kem as u8]).unwrap();
        slot.put(3, &vec![0u8; enc_len]).unwrap();
        slot.put(4, &[]).unwrap();
        slot.put(5, &[0x66; 32]).unwrap();
        slot.put(7, &[0u8; 24]).unwrap();
        slot.put(8, &[0x99; 32]).unwrap();
        let mut slots = TlvWriter::new();
        slots.put(0, &slot.finish()).unwrap();
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish())
    };

    // Контроль: единица с 32 нулями обязана разбираться, иначе зелёный отказ
    // ниже не отличался бы от «отвергается вообще всё».
    assert!(
        Header::decode(&claim_with(KemAlg::X25519HkdfSha256, 32)).is_ok(),
        "честный слот кода-претензии отвергнут"
    );

    // P-256 с его законными 65 нулями — и всё же отказ: механизм у этого слота
    // не выбирается.
    assert!(
        Header::decode(&claim_with(KemAlg::P256HkdfSha256, 65)).is_err(),
        "слот кода-претензии с kem_id = 2 принят: байты claim.cc перестали быть \
            однозначными"
    );

    // И писатель обязан отказывать там же, где читатель. Наш писатель не должен
    // уметь произвести то, что наш же читатель обязан отвергнуть.
    let mut header = sample_header();
    header.key_slots = vec![KeySlot::Known(KnownSlot {
        kind: SlotKind::RecipientClaim,
        kem: KemAlg::P256HkdfSha256,
        enc: vec![0u8; 65],
        nonce: [0u8; 24],
        ct: Vec::new(),
        commitment: [0x66; 32],
        key_fpr: None,
        claim_commit: Some([0x99; 32]),
    })];
    assert!(
        header.encode().is_err(),
        "писатель произвёл слот кода-претензии на P-256 — читатель обязан его \
            отвергнуть, значит производить его нельзя"
    );
}

/// Механизм, форму которого не задаёт НИ ОДНА версия, пропускается — в контейнере
/// версии 2, где P-256 уже разбирается.
///
/// Пара к тесту выше, и без неё покрытие было бы половинчатым. Тот прибит к версии
/// 1 и стережёт, чтобы версия 1 не обрела семантику задним числом; этот стережёт
/// саму ветку пропуска — что она жива в текущей версии, а не осталась в прошлой.
///
/// `kem_id = 3` (RSA-OAEP) выбран потому, что его номер в реестре занят, а форма не
/// задана и не планируется: `KemAlg::from_u8` считает его знакомым, то есть ветка
/// «незнакомый номер» для него не наступает, и слот обязан пропускаться именно по
/// неопределённости формы. Ровно тот случай, который однажды рушил весь контейнер.
///
/// Длина `enc` здесь намеренно не похожа ни на 32, ни на 65: у RSA-OAEP инкапсуляция
/// занимает сотни байт, и проверять чужую форму своей мерой — то самое, чего делать
/// нельзя.
#[test]
fn a_mechanism_no_version_defines_is_still_skipped_in_version_two() {
    let mut foreign = TlvWriter::new();
    foreign.put(1, &(SlotKind::RecipientIdentity as u16).to_le_bytes()).unwrap();
    foreign.put(2, &[KemAlg::RsaOaepSha256 as u8]).unwrap();
    foreign.put(3, &vec![0xcd; 256]).unwrap();
    foreign.put(4, &[0x55; 48]).unwrap();
    foreign.put(5, &[0x66; 32]).unwrap();
    foreign.put(6, &vec![0xcd; 256]).unwrap();
    foreign.put(7, &[0x01; 24]).unwrap();

    let mut slots = TlvWriter::new();
    slots.put(0, &foreign.finish()).unwrap();
    let header =
        replace_field(&sample_header_at(2).encode().unwrap(), htag::KEY_SLOTS, &slots.finish());

    let parsed = Header::decode(&header).expect(
        "контейнер версии 2 отвергнут целиком из-за слота на механизме без заданной формы: \
         обещание §3.3 не выполняется",
    );
    assert!(
        matches!(parsed.header.key_slots.first(), Some(KeySlot::Unknown { .. })),
        "слот RSA-OAEP разобран как пригодный: {:?}",
        parsed.header.key_slots.first()
    );
}

/// Сжатая точка P-256 отвергается ФОРМАТОМ, и заявление об этом стоит здесь.
///
/// Проверка была заявлена не там. В `oc-crypto` жила проба «P-256 не принимает
/// сжатую форму», кормившая `agree` тридцатью тремя байтами `0x04`; отказ приходил
/// от разбора SEC1 (`0x04` — префикс НЕсжатой точки, так не выглядит ни одна из
/// двух форм), а не от формы, и свойства, о котором она говорила, у слоя
/// согласования нет: `from_sec1_bytes` разбирает обе формы и обе дают один секрет.
///
/// Запрет живёт в таблице точных длин (§3.3: `enc` при `kem_id = 2` — ровно 65
/// байт, несжатая точка SEC1 `0x04 ‖ X ‖ Y`), и держит его И-8. Причина в спеке
/// названа и она про БАЙТЫ: две допустимые формы одного ключа дали бы для одного
/// получателя две разные записи слота, а значит разошедшиеся `core_hash` и подпись
/// у двух добросовестных реализаций.
///
/// Требуется ИМЕННО `BadFieldLength { tag: ENC }`: «любая ошибка» — та самая
/// формулировка, из-за которой прежняя проба зеленела не по своей причине.
#[test]
fn a_compressed_p256_point_is_refused_by_the_exact_length_table() {
    // Слот P-256 версии 2, отличающийся от корректного ровно длиной `enc`.
    let slot = |enc_len: usize| {
        let mut w = TlvWriter::new();
        w.put(1, &(SlotKind::AuthorDevice as u16).to_le_bytes()).unwrap();
        w.put(2, &[KemAlg::P256HkdfSha256 as u8]).unwrap();
        // Первый байт — префикс несжатой точки: содержимое `enc` формат не
        // разбирает, и отказ обязан прийти от длины, а не от вида байтов.
        let mut enc = vec![0x04u8];
        enc.resize(enc_len, 0xcd);
        w.put(3, &enc).unwrap();
        w.put(4, &[0x55; 48]).unwrap();
        w.put(5, &[0x66; 32]).unwrap();
        w.put(7, &[0x01; 24]).unwrap();
        let mut slots = TlvWriter::new();
        slots.put(0, &w.finish()).unwrap();
        replace_field(&sample_header_at(2).encode().unwrap(), htag::KEY_SLOTS, &slots.finish())
    };

    // Несжатая форма — слот пригоден. Без этого случая «отказ на 33 байтах» не
    // отличить от «P-256 в версии 2 не разбирается вовсе».
    let parsed = Header::decode(&slot(65)).expect("слот P-256 с несжатой точкой отвергнут");
    assert!(
        matches!(parsed.header.key_slots.first(), Some(KeySlot::Known(_))),
        "слот P-256 с несжатой точкой не разобран как пригодный: {:?}",
        parsed.header.key_slots.first()
    );

    // Сжатая форма — отказ по длине `enc`, а не пропуск слота как незнакомого.
    match Header::decode(&slot(33)) {
        Err(FormatError::BadFieldLength { tag, len }) => {
            assert_eq!(tag, 3, "отказ пришёл не от длины `enc`");
            assert_eq!(len, 33, "отвергнута не та длина");
        }
        other => panic!("сжатая точка P-256 принята форматом: {other:?}"),
    }
}
