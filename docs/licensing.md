# Licensing

Open Crate uses the [Open Crate Community License 1.0](../LICENSE).
It is source-available, not OSI-approved open source. The complete license is
authoritative; this page is an explanation.

| Use | Terms |
| --- | --- |
| Personal, non-commercial projects and learning | Free |
| Non-commercial academic teaching and research | Free |
| Company with **both** less than $1M annual group revenue and fewer than 25 people | Free, including commercial projects |
| Company reaching either threshold | Commercial agreement required; an existing qualifying user gets a 90-day transition |
| Evaluation and non-production security auditing | Free regardless of company size |

Thresholds apply to the entire corporate group, not one developer team. Revenue
means gross revenue from all activities over the preceding twelve months, not
profit or revenue from one project. Investment and loan proceeds are excluded.
Employees and individual contractors count toward headcount. An independent
commercial developer qualifies under the same business rules; working alone
does not create an unlimited revenue exemption.

No activation, compulsory telemetry, paid account or paperwork is needed to
exercise the free grant. There are no fees for past use that was permitted.
Redistribution must retain the license, and each recipient must independently
qualify. Creating a document does not license that document under these terms.

## Commercial agreements

Write to **god@closecrate.com** (the contact route on
[closecrate.com](https://closecrate.com/) named in section 5 of the license),
or open the **Licensing enquiry** issue template in this repository, which is
the licensing issue category named in the same section. E-mail is private;
issues are public, so in an issue state only the kind of use and a private
contact, and keep revenue figures, headcount, contracts and customer names out
of it.

An enquiry proceeds in writing, in this order:

1. The maintainer confirms which use is being licensed and which group is
   covered, and moves the conversation to the private contact you gave.
2. You receive a written offer that states the price, the covered group, the
   term, what is and is not included, the payment method and the payee.
   Nothing is owed and nothing is granted before that offer is accepted.
3. Both sides sign a commercial license agreement; the free-grant conditions
   of sections 3 and 4 of the Community License stop applying to the covered
   group for the agreed term.
4. Payment is made as the agreement says. A payment made without a signed
   agreement does not create a license.

What the agreement covers is fixed by the license itself: fee, scope, term,
payment method, support and any warranty are agreed separately in writing.
Expect an annual company license for production use of the five core crates,
with integration help and support priced separately. No per-document or
per-user metering is planned for the core. Close Crate hosting and application
services are separate purchases.

Until the first agreement is signed, there is no published price list. Do not
infer a price from any third-party licensing model mentioned in this
repository's history or documentation.

## Third-party code

This is the first public Open Crate release candidate. The core is offered under
the Community License, without an alternative MIT/Apache grant. Dependencies
retain their own licenses. Inspect their inventory with `cargo metadata --locked`
and `cargo deny check licenses`.

This custom license has not received an independent legal review. A commercial
contract and working sales channel are still needed to turn inquiries into
payments.
