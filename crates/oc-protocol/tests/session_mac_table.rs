//! MAC сессии: таблица заверяемых видов и отделение хвоста — в крейте-владельце.
//!
//! Зачем отдельный файл, если сервер и так отбивает подменённый кадр шестью
//! пробами `cc-authority/tests/session_mac.rs`. Затем, что ОБЕ величины живут
//! ЗДЕСЬ, а стерёг их до сих пор только сосед. Мутация «убрать `KIND_ACTIVATE`
//! из [`is_session_sealed`]» не роняла ни одной из 104 проб `oc-protocol` —
//! а это снятие MAC с активации целиком: клиент по той же таблице решает,
//! ставить ли хвост, и обе стороны дружно перестают его требовать. Докстрока
//! функции прямо называет её «одной таблицей на обе стороны провода»; у такой
//! величины проба обязана быть там, где она объявлена, а не только там, где
//! её однажды применили.
//!
//! Проба идёт ПО ПУТИ: вид берётся не из константы, а из первого байта кадра,
//! который собрал [`encode_request`] — ровно так его читают и `cc_cli::activate`
//! (`seal_request`), и `cc_authority::serve` (`converse`). Сравнение с числом 3
//! пережило бы переименование варианта; сборка кадра — нет.

// Литы сняты по названным причинам: `unwrap`/`panic` — словарь проверки,
// индексирование — чтение первого байта кадра заведомо непустой длины.
// В продуктовом коде запреты остаются в силе.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use oc_protocol::activation::{
    ActivateReq, ClockReport, Hello, Proof, Request, SlotBlob, encode_request, is_session_sealed,
    split_request_mac,
};

fn activate_req() -> Box<ActivateReq> {
    Box::new(ActivateReq {
        file_id: [0x41; 16],
        policy_hash: [0x33; 32],
        device_fpr: [0x22; 32],
        device_kem: 1,
        device_public: vec![0x22; 32],
        server_slot: SlotBlob { enc: vec![0x01; 32], nonce: [0x02; 24], ct: vec![0x03; 48] },
        lease_seconds: 3600,
        device_clock: Some(ClockReport { reset_count: 1, clock_ms: 1000, read_at: 1_756_000_000 }),
        operation_id: None,
    })
}

fn evidence() -> oc_protocol::attestation::Evidence {
    oc_protocol::attestation::Evidence {
        ek_public: vec![0x11; 32],
        ek_certificate: None,
        intermediates: Vec::new(),
        identity_public: vec![0x12; 32],
        attest: vec![0x13; 32],
        signature: vec![0x14; 64],
        device_public: vec![0x15; 32],
    }
}

/// ВИД КАДРА РЕШАЕТ, ЗАВЕРЯЕТСЯ ЛИ ОН MAC СЕССИИ, И РЕШЕНИЕ ЗДЕСЬ ВЫПИСАНО ПОИМЁННО.
///
/// Заверяются те и только те виды, чьё тело МЕНЯЕТ ИСХОД разговора и при этом
/// приходит ПОСЛЕ рукопожатия: активация и продление (показания часов в них
/// двигают планку анти-отката навсегда — находка Н-2) и три шага аттестации,
/// вердикт которых меняет, что выдаст активация этого же разговора (B6b).
///
/// Рукопожатие — `Hello` и `Prove` — заверяться не может и не должно: ключа
/// сессии до него ещё нет, он из этого разговора и выводится. Потребуй мы MAC
/// здесь — рукопожатие стало бы невозможным; не потребуй у активации — MAC не
/// стало бы вовсе.
#[test]
fn the_kinds_sealed_by_the_session_mac_are_the_named_ones() {
    // (имя для сообщения, запрос, обязан ли нести хвост K25)
    let cases: [(&str, Request, bool); 9] = [
        ("Activate", Request::Activate(activate_req()), true),
        ("Renew", Request::Renew(activate_req()), true),
        ("AttestOpen", Request::AttestOpen, true),
        ("AttestEvidence", Request::AttestEvidence(Box::new(evidence())), true),
        ("AttestSecret", Request::AttestSecret([0x77; 32]), true),
        (
            "Hello",
            Request::Hello(Hello {
                device_fpr: [0x22; 32],
                device_public: [0x22; 32],
                device_tpm: None,
                device_hybrid: None,
            }),
            false,
        ),
        ("Prove", Request::Prove(Proof { echo: vec![0x44; 32] }), false),
        ("Requests", Request::Requests { file_id: [0x41; 16] }, false),
        ("Revocation", Request::Revocation { file_id: [0x41; 16] }, false),
    ];

    for (name, request, sealed) in cases {
        let framed = encode_request(&request).expect("запрос не кодируется");
        let kind = framed[0];
        assert_eq!(
            is_session_sealed(kind),
            sealed,
            "вид кадра `{name}` (байт {kind}): таблица MAC сессии говорит {}, а обязана {}. \
             Таблица одна на обе стороны провода — снятое здесь снимается и у клиента, \
             и у сервера разом, и MAC исчезает молча",
            is_session_sealed(kind),
            sealed
        );
    }
}

/// ХВОСТ ОТДЕЛЯЕТСЯ ЦЕЛИКОМ, А ТЕЛО ПОД MAC — ВЕСЬ КАДР ВМЕСТЕ С БАЙТОМ ВИДА.
///
/// Два свойства одной строкой, и оба несущие. Первое: под MAC идёт байт вида —
/// иначе посредник менял бы `Activate` на `Renew` в перехваченном кадре, не
/// трогая хвоста, и продление проходило бы за активацию. Второе: отделённое
/// тело — РОВНО то, что уйдёт в разбор, байт в байт, без хвоста; оставь в нём
/// хоть байт MAC — и разбор увидел бы поле, которого отправитель не писал.
#[test]
fn the_mac_tail_splits_off_whole_and_leaves_the_kind_byte_under_the_mac() {
    let framed = encode_request(&Request::Activate(activate_req())).unwrap();
    let mut sealed = framed.clone();
    let tail = [0x9e_u8; 32];
    sealed.extend_from_slice(&tail);

    let (body, mac) = split_request_mac(&sealed).expect("кадр с хвостом не разделился");
    assert_eq!(body, framed.as_slice(), "тело под MAC не совпало с кадром: хвост отделён не целиком");
    assert_eq!(body[0], framed[0], "байт вида выпал из тела под MAC");
    assert_eq!(mac, &tail, "хвост взят не с конца кадра");
}

/// КАДР КОРОЧЕ ХВОСТА ИЛИ РАВНЫЙ ЕМУ — ОТКАЗ, А НЕ ПУСТОЕ ТЕЛО.
///
/// Ровно 32 байта — это «тело пустое, весь кадр и есть MAC». Прими мы такое,
/// и у кадра не стало бы даже байта вида, по которому выбирается ветка; отказ
/// здесь дешевле любой догадки о том, чем считать пустоту.
#[test]
fn a_frame_no_longer_than_the_tail_is_refused() {
    for len in [0_usize, 1, 31, 32] {
        let short = vec![0x03_u8; len];
        assert!(
            split_request_mac(&short).is_err(),
            "кадр длиной {len} разделился, хотя тела в нём нет"
        );
    }
    assert!(split_request_mac(&[0x03_u8; 33]).is_ok(), "кадр из тела в один байт и хвоста отбит");
}
