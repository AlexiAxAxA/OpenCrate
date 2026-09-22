//! Лизинг версии 2: сервер везёт получателю СВОЙ профиль под своей подписью.
//!
//! Проверяется не «поле сохранилось», а три свойства, ради которых поле заведено:
//! документ с профилем НЕ выглядит как прежний (иначе клиент прежней сборки
//! молча пропустил бы ужесточение), профиль покрыт подписью (иначе его снял бы
//! любой, кто держит провод), и версия сходится с составом полей в обе стороны.

// Индексирование, срезы и паника разрешены ЗДЕСЬ и только здесь: проба правит
// байты заведомо известной раскладки, и выход за край обязан уронить прогон, а
// не тихо пройти мимо. В продуктовом коде эти литы остаются в силе.
#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use oc_crypto::sign::Signer as _;
use oc_protocol::lease::{self, Lease, LEASE_VERSION, LEASE_VERSION_WITH_SERVER_POLICY, tag};
use oc_format::FormatError;
use oc_policy::{Action, Binding, LeaseFacts, Network, Policy, Timestamp, TpmClock};

/// Профиль сервера: смотреть можно, выгружать нельзя, привязка не ниже железа.
fn profile() -> Policy {
    let mut policy = Policy::deny_all().allow(Action::View);
    policy.min_binding = Binding::Hardware;
    policy.max_opens = Some(3);
    policy.network = Network::Lease { seconds: 3_600, max_offline_seconds: 600 };
    policy
}

fn facts(server_policy: Option<Policy>) -> LeaseFacts {
    LeaseFacts {
        device_fingerprint: [0x22; 32],
        policy_hash: [0x33; 32],
        seq: 7,
        epoch: 2,
        issued_at: Timestamp(1_700_000_000),
        expires_at: Timestamp(1_700_086_400),
        opens_remaining: Some(5),
        revoked: false,
        // Часы намеренно ПРИСУТСТВУЮТ: их тег 11, у профиля 12, и порядок полей
        // строго возрастает (И-7). Проба без часов не отличила бы правильный
        // порядок от обратного — а обратный отказал бы на записи.
        tpm_clock: Some(TpmClock { reset_count: 3, clock_ms: 123_456 }),
        server_policy,
        attested: None,
    }
}

fn lease(server_policy: Option<Policy>) -> Lease {
    Lease { file_id: [0x11; 16], facts: facts(server_policy) }
}

fn server() -> oc_crypto::sign::Ed25519Signer {
    oc_crypto::sign::Ed25519Signer::from_seed(&[0x5a; 32])
}

/// Значение поля версии лежит первым полем: тег(2) ‖ длина(4) ‖ значение(2).
fn set_version(body: &mut [u8], version: u16) {
    assert_eq!(u16::from_le_bytes([body[0], body[1]]), tag::VERSION, "версия не первое поле");
    assert_eq!(u32::from_le_bytes([body[2], body[3], body[4], body[5]]), 2, "версия не u16");
    body[6..8].copy_from_slice(&version.to_le_bytes());
}

/// Профиль доезжает целиком, и документ при этом ОБЪЯВЛЯЕТ себя версией 2.
///
/// Обе половины важны. Круг без версии означал бы, что ужесточение доехало до
/// нас — но ничего не говорил бы о том, что случится у клиента, собранного до
/// появления поля.
#[test]
fn a_profile_travels_whole_and_the_document_calls_itself_version_two() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();

    assert_eq!(
        u16::from_le_bytes([body[6], body[7]]),
        LEASE_VERSION_WITH_SERVER_POLICY,
        "документ с профилем не назвался версией 2"
    );
    assert_eq!(lease::decode(&body).unwrap(), lease(Some(profile())));
}

/// Без профиля версия прежняя — байт в байт то, что было до B4a.
///
/// Это условие того, что замороженный вектор `tests/kat/lease.kat` остаётся
/// верен (И-14): новое поле не имеет права менять документы, в которых его нет.
#[test]
fn without_a_profile_the_document_stays_version_one() {
    let body = lease::encode(&lease(None)).unwrap();

    assert_eq!(u16::from_le_bytes([body[6], body[7]]), LEASE_VERSION);
    assert_eq!(lease::decode(&body).unwrap().facts.server_policy, None);
}

/// Версия 1 с профилем отвергается: критичное поле, которого в этой версии нет.
///
/// Так выглядит попытка протащить ужесточение мимо версии — и так же выглядит
/// сервер, забывший поднять версию. Разбирать такой документ нельзя ни в каком
/// из двух случаев: приняв его, мы приняли бы правило, о котором договорённости
/// нет.
#[test]
fn version_one_carrying_a_profile_is_refused() {
    let mut body = lease::encode(&lease(Some(profile()))).unwrap();
    set_version(&mut body, LEASE_VERSION);

    match lease::decode(&body) {
        Err(FormatError::UnknownCriticalField { tag }) => {
            assert_eq!(tag, tag::SERVER_POLICY);
        }
        other => panic!("версия 1 с профилем разобрана: {other:?}"),
    }
}

/// Версия 2 без профиля отвергается: обещанное поле пропало по дороге.
///
/// Именно так выглядит снятие ужесточения вырезанием поля. Подпись такую правку
/// и так не переживёт, но разборщик обязан отказать САМ: он вызывается и там,
/// где подпись проверяют после него, и «поле молча исчезло» не должно иметь
/// исхода «доступ шире».
#[test]
fn version_two_without_a_profile_is_refused() {
    let mut body = lease::encode(&lease(None)).unwrap();
    set_version(&mut body, LEASE_VERSION_WITH_SERVER_POLICY);

    match lease::decode(&body) {
        Err(FormatError::MissingField { tag }) => assert_eq!(tag, tag::SERVER_POLICY),
        other => panic!("версия 2 без профиля разобрана: {other:?}"),
    }
}

/// Версия из будущего отвергается по номеру, до разбора полей.
///
/// Ровно это и делает клиент прежней сборки, встретив нашу версию 2: он не
/// знает поля 12 и не обязан его понимать — он видит незнакомую версию и
/// отказывает. Проверить это «изнутри» нечем, поэтому проверяется механизм:
/// незнакомый номер — отказ, а не разбор по мере сил. Номер из будущего — 4:
/// третью занял признак аттестации (B6b).
#[test]
fn an_unknown_version_is_refused_by_its_number() {
    let mut body = lease::encode(&lease(Some(profile()))).unwrap();
    set_version(&mut body, 4);

    match lease::decode(&body) {
        Err(FormatError::UnsupportedLeaseVersion { version }) => assert_eq!(version, 4),
        other => panic!("версия 4 разобрана: {other:?}"),
    }
}

/// Правка ЛЮБОГО байта профиля ломает подпись сервера.
///
/// Перебором по всей области профиля: подпись обязана покрывать её целиком.
/// Профиль лежит последним полем — местом, которое пропускают первым.
#[test]
fn flipping_any_byte_of_the_profile_breaks_the_signature() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    let plain = lease::encode(&lease(None)).unwrap();
    // Всё, что длиннее документа без профиля, и есть профиль с его заголовком.
    let from = plain.len();
    assert!(from < body.len(), "профиль не добавил ни байта");

    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    for i in from..body.len() {
        let mut damaged = body.clone();
        damaged[i] ^= 0x01;
        assert!(
            lease::verify(&damaged, &sig, &signer.public_key()).is_err(),
            "подпись пережила правку байта {i} профиля: он не покрыт"
        );
    }
}

/// Профиль нельзя срезать: укороченное тело не принимается подписью.
///
/// Отдельной пробой от правки байта, потому что защищает другое. Правка меняет
/// содержание ужесточения, срез — снимает его целиком, и снятие выгоднее
/// противнику: оно возвращает права автора, то есть максимум из достижимого.
#[test]
fn cutting_the_profile_off_is_not_accepted() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    let mut cut = lease::encode(&lease(None)).unwrap();
    set_version(&mut cut, LEASE_VERSION_WITH_SERVER_POLICY);
    assert!(
        lease::verify(&cut, &sig, &signer.public_key()).is_err(),
        "подпись принята для тела со срезанным профилем"
    );
}

/// Лизинг версии 2 сходится с собственным замороженным вектором.
///
/// Вектор ОТДЕЛЬНЫМ файлом, а не строкой в `lease.kat`: тот заморожен вместе с
/// документом версии 1 и меняться не вправе (И-14). Новый документ — новый
/// файл; это добавление свидетеля, а не перевыпуск старого.
#[test]
fn the_version_two_lease_matches_its_frozen_vector() {
    let v = load_kat("lease-v2.kat");
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    assert_eq!(hex(&body), v["lease_body"], "байты тела лизинга версии 2 разошлись с вектором");

    let signer = server();
    assert_eq!(hex(&signer.public_key()), v["lease_verify_key"]);

    let sig: [u8; 64] = hex_bytes(&v["lease_signature"]).try_into().unwrap();
    lease::verify(&body, &sig, &signer.public_key())
        .expect("замороженная подпись версии 2 не принята: транскрипт разошёлся");

    // И обратно: Ed25519 детерминирован, поэтому совпадение — требование.
    let fresh = signer.sign(&lease::signing_transcript(&body)).unwrap();
    assert_eq!(hex(&fresh), v["lease_signature"]);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn load_kat(name: &str) -> std::collections::BTreeMap<String, String> {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| !k.trim_start().starts_with('#'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Выпустить вектор лизинга версии 2. Инструмент, не проверка.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_version_two_lease_vector() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    let policy =
        oc_format::policy_codec::encode(oc_format::header::CONTAINER_VERSION, &profile()).unwrap();
    println!("lease_verify_key = {}", hex(&signer.public_key()));
    println!("lease_body = {}", hex(&body));
    println!("lease_signature = {}", hex(&sig));
    println!("# профиль сервера отдельно: {}", hex(&policy));
}
