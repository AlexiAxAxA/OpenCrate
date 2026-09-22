//! Подпись лизинга: круг от выдачи до проверки, и все способы её не принять.
//!
//! Отдельным файлом, а не в модуле: здесь нужен настоящий подписывающий ключ, то
//! есть `oc-crypto` целиком, а модульные тесты формата обходятся без него.

// Индексирование и срезы разрешены ЗДЕСЬ и только здесь: тест перебирает байты
// заведомо известной длины и читает вектор, отсутствие ключа в котором обязано
// уронить прогон, а не тихо пройти. В продуктовом коде эти литы остаются в силе.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Чтение файла разрешено ЗДЕСЬ и только здесь, тем же порядком, что в
    // crates/oc-crypto/tests/kat.rs: вектор лежит вне кода намеренно, чтобы
    // вторая реализация могла свериться, не читая наш Rust. Запрет часов, файлов
    // и сети остаётся в силе для самого крейта — он и проверяется отдельным
    // прогоном clippy по трём крейтам.
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use oc_crypto::sign::Signer as _;
use oc_format::FormatError;
use oc_format::tlv::TlvWriter;
use oc_protocol::lease::{self, Lease};
use oc_policy::{LeaseFacts, Timestamp, TpmClock};

fn sample() -> Lease {
    Lease {
        file_id: [0x11; 16],
        facts: LeaseFacts {
            device_fingerprint: [0x22; 32],
            policy_hash: [0x33; 32],
            seq: 7,
            epoch: 2,
            issued_at: Timestamp(1_700_000_000),
            expires_at: Timestamp(1_700_086_400),
            opens_remaining: Some(5),
            revoked: false,
            tpm_clock: Some(TpmClock { reset_count: 3, clock_ms: 123_456 }),
            server_policy: None,
            attested: None,
        },
    }
}

fn server() -> oc_crypto::sign::Ed25519Signer {
    oc_crypto::sign::Ed25519Signer::from_seed(&[0x5a; 32])
}

/// Лизинг, подписанный сервером, проверяется его же ключом.
#[test]
fn a_lease_signed_by_the_server_verifies_with_its_key() {
    let body = lease::encode(&sample()).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    lease::verify(&body, &sig, &signer.public_key()).expect("своя подпись не принята");
    assert_eq!(lease::decode(&body).unwrap(), sample());
}

/// Подпись ЧУЖОГО сервера не принимается.
///
/// Это и есть защита от поддельного сервера: ключ проверки лежит в заголовке под
/// подписью автора, и подменить его нельзя, не подменив заголовок.
#[test]
fn a_lease_signed_by_another_server_is_refused() {
    let body = lease::encode(&sample()).unwrap();
    let sig = server().sign(&lease::signing_transcript(&body)).unwrap();

    let stranger = oc_crypto::sign::Ed25519Signer::from_seed(&[0x77; 32]);
    assert!(
        lease::verify(&body, &sig, &stranger.public_key()).is_err(),
        "лизинг принят по ключу другого сервера"
    );
}

/// Правка ЛЮБОГО байта тела ломает подпись.
///
/// Перебором по всем позициям, а не выборочно: подпись обязана покрывать тело
/// целиком, и «покрывает почти всё» — это дыра ровно там, где её не проверили.
/// Дороже всего пропустить хвост: поле часов необязательное и лежит последним.
#[test]
fn flipping_any_byte_of_the_body_breaks_the_signature() {
    let body = lease::encode(&sample()).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    for i in 0..body.len() {
        let mut damaged = body.clone();
        damaged[i] ^= 0x01;
        assert!(
            lease::verify(&damaged, &sig, &signer.public_key()).is_err(),
            "подпись пережила правку байта {i}: он не покрыт"
        );
    }
}

/// Подпись одного лизинга не переносится на другой.
///
/// Самая дешёвая атака из возможных: взять своё честное разрешение и подставить
/// в него чужой file_id или чужое устройство. Проверяются обе подмены отдельно,
/// потому что защищает их одно и то же — но проверять надо каждую.
#[test]
fn a_signature_does_not_travel_to_another_file_or_device() {
    let signer = server();
    let original = sample();
    let body = lease::encode(&original).unwrap();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    let mut other_file = original.clone();
    other_file.file_id = [0x99; 16];
    let other_body = lease::encode(&other_file).unwrap();
    assert!(
        lease::verify(&other_body, &sig, &signer.public_key()).is_err(),
        "подпись перенесена на другой файл"
    );

    let mut other_device = original;
    other_device.facts.device_fingerprint = [0x99; 32];
    let other_body = lease::encode(&other_device).unwrap();
    assert!(
        lease::verify(&other_body, &sig, &signer.public_key()).is_err(),
        "подпись перенесена на другое устройство"
    );
}

/// Собрать документ ЦЕЛИКОМ: `подпись(64) ‖ тело`.
///
/// Отдельной функцией, потому что именно эту раскладку принимает комбинатор
/// [`lease::verify_signed`], а пробы выше работают с половинками — телом и
/// подписью по отдельности. Ровно из-за этого комбинатор не звала ни одна из
/// них: мутация «проверка подписи в `verify_signed` снята целиком» оставалась
/// незамеченной, хотя продукт (`cc_cli::lease`) ходит только через него.
fn signed(lease: &Lease, signer: &oc_crypto::sign::Ed25519Signer) -> Vec<u8> {
    let body = lease::encode(lease).unwrap();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    let mut out = sig.to_vec();
    out.extend_from_slice(&body);
    out
}

/// Честный документ проходит комбинатор и разбирается в то, что подписали.
#[test]
fn the_lease_combinator_accepts_the_servers_own_document() {
    let signer = server();
    let bytes = signed(&sample(), &signer);
    assert_eq!(
        lease::verify_signed(&bytes, &signer.public_key()).unwrap(),
        sample(),
        "своя выдача не прошла комбинатор"
    );
}

/// Чужой ключ, битая подпись и битое тело — отказ, и отказ ИМЕННО подписной.
///
/// Перебор по КАЖДОМУ байту подписи и КАЖДОМУ байту тела, а не по трём
/// выбранным позициям: «покрывает почти всё» — это дыра ровно там, где не
/// проверили. Сверяется не `is_err()`, а конкретный код: комбинатор, начавший
/// отвечать на подделку кодом РАЗБОРА, сообщает противнику о содержимом
/// незаверенных байтов, и именно это запрещает И-5.
#[test]
fn the_lease_combinator_refuses_a_foreign_key_a_broken_signature_and_a_broken_body() {
    let signer = server();
    let stranger = oc_crypto::sign::Ed25519Signer::from_seed(&[0x77; 32]);
    let bytes = signed(&sample(), &signer);

    assert!(
        matches!(
            lease::verify_signed(&bytes, &stranger.public_key()),
            Err(FormatError::BadHeaderSignature)
        ),
        "лизинг принят по ключу другого сервера"
    );

    for i in 0..lease::SIGNATURE_LEN {
        let mut damaged = bytes.clone();
        damaged[i] ^= 0x01;
        assert!(
            matches!(
                lease::verify_signed(&damaged, &signer.public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "правка байта подписи {i} не отвергнута как несошедшаяся подпись"
        );
    }

    for i in lease::SIGNATURE_LEN..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[i] ^= 0x01;
        assert!(
            matches!(
                lease::verify_signed(&damaged, &signer.public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "правка байта тела {i} не отвергнута как несошедшаяся подпись"
        );
    }
}

/// ЛЮБОЙ обрубок отвергается как несошедшаяся подпись, а не как обрезание.
///
/// Перебираются все длины от нуля до полной. Короче подписи — документа нет
/// вовсе; длиннее подписи, но короче целого — подпись не сходится с укороченным
/// телом. Оба случая обязаны выглядеть одинаково: различие здесь сообщало бы,
/// докуда именно противник угадал.
#[test]
fn the_lease_combinator_refuses_every_truncation_as_a_signature_failure() {
    let signer = server();
    let bytes = signed(&sample(), &signer);
    for cut in 0..bytes.len() {
        assert!(
            matches!(
                lease::verify_signed(&bytes[..cut], &signer.public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "обрубок длины {cut} принят или отвергнут не как подпись"
        );
    }
}

/// ПОДПИСЬ ПРОВЕРЯЕТСЯ ДО РАЗБОРА ТЕЛА — сторож на порядок двух строк.
///
/// Тело здесь заведомо НЕРАЗБИРАЕМО, подпись заведомо ЧУЖАЯ. Правильный ответ
/// ровно один — `BadHeaderSignature`; любой код разбора означает, что тело
/// успели прочитать до проверки подлинности, то есть различимые отказы
/// сообщаются о байтах, которых никто не подписывал (довод И-5, он же записан в
/// докстроке `revocation::verify_signed`).
///
/// До этой пробы порядок держался на комментарии: перестановка `decode` перед
/// `verify` не роняла ни одной проверки — пробы на коды разбора звали `decode`
/// напрямую, а пробы на подпись подавали разбираемое тело, и случай, где
/// встречаются оба, не проверял никто.
#[test]
fn the_lease_signature_is_checked_before_the_body_is_parsed() {
    let signer = server();
    let stranger = oc_crypto::sign::Ed25519Signer::from_seed(&[0x77; 32]);

    // Два разных способа быть неразбираемым, потому что ветки разбора разные:
    // нет обязательного поля и незнакомый критичный тег.
    let empty = TlvWriter::new().finish().to_vec();
    let mut w = TlvWriter::new();
    w.put(0x7FFF, &[0xab; 4]).unwrap();
    let unknown_critical = w.finish().to_vec();

    for (what, body) in [("пустое тело", empty), ("чужой критичный тег", unknown_critical)] {
        assert!(
            lease::decode(&body).is_err(),
            "{what}: предпосылка пробы неверна, тело разбирается"
        );

        // Подпись настоящая, но ЧУЖАЯ: подделать документ противник умеет, а
        // подписать ключом сервера — нет.
        let sig = stranger.sign(&lease::signing_transcript(&body)).unwrap();
        let mut bytes = sig.to_vec();
        bytes.extend_from_slice(&body);

        let outcome = lease::verify_signed(&bytes, &signer.public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadHeaderSignature)),
            "{what}: разбор произошёл до проверки подписи, ответ {outcome:?} — \
             подделка сообщает о себе кодом разбора незаверенных байтов"
        );
    }
}

/// Разбор произвольных байтов не паникует.
///
/// Лизинг приходит по сети, то есть от противника, и паника здесь — отказ в
/// обслуживании ровно там, где ввод враждебен по определению.
#[test]
fn decoding_arbitrary_bytes_never_panics() {
    let body = lease::encode(&sample()).unwrap();

    for cut in 0..body.len() {
        let _ = lease::decode(&body[..cut]);
    }
    let mut seed = 0x5eed_u64;
    for _ in 0..20_000 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let len = (seed >> 33) as usize % 96;
        let mut junk = vec![0u8; len];
        for (i, b) in junk.iter_mut().enumerate() {
            *b = (seed >> (i % 8 * 8)) as u8;
        }
        let _ = lease::decode(&junk);
    }
}

/// Лизинг сходится с замороженным вектором — тело, подпись и ключ.
///
/// Заморожена и подпись, а не только тело, и это существенно: тело само по себе
/// ничего не значит, лизинг — утверждение сервера. Оставив на свободе транскрипт,
/// мы оставили бы на свободе то, ЧТО именно подписано, а расхождение там
/// молчаливо — подпись не сойдётся, и выглядеть будет как «сервер сломался».
#[test]
fn the_lease_matches_its_frozen_vector() {
    let v = load_kat("lease.kat");
    let body = lease::encode(&sample()).unwrap();
    assert_eq!(hex(&body), v["lease_body"], "байты тела лизинга разошлись с вектором");

    let signer = server();
    assert_eq!(hex(&signer.public_key()), v["lease_verify_key"]);

    let sig: [u8; 64] = hex_bytes(&v["lease_signature"]).try_into().unwrap();
    lease::verify(&body, &sig, &signer.public_key())
        .expect("замороженная подпись не принята: транскрипт разошёлся");

    // И обратно: подпись, снятая сейчас, совпадает с замороженной. Ed25519
    // детерминирован, поэтому это законное требование, а не удача.
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
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/kat")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| !k.trim_start().starts_with('#'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Выпустить вектор лизинга. Инструмент, не проверка.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_lease_vector() {
    let body = lease::encode(&sample()).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("lease_verify_key = {}", hex(&signer.public_key()));
    println!("lease_body = {}", hex(&body));
    println!("lease_signature = {}", hex(&sig));
}
