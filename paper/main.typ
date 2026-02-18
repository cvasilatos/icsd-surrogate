#import "@preview/clean-acmart:0.0.1": acmart, acmart-ccs, acmart-keywords, acmart-ref, to-string
#set par.line(numbering: n => text(red)[#n])

#let project = json("resources/metadata.json")

#let title = [#project.name: #project.title]

#let conference = (
  name: [ACM SIGSAC 33rd ACM Conference on Computer and Communications Security (CCS)],
  short: [CCS ’26],
  year: [2026],
  date: [November 15-19],
  venue: [The Hague, The Netherlands],
)
#let doi = "https://doi.org/10.1145/0000000000"

#let authors = (
  (name: "Christoforos Vasilatos", email: "cv43@nyu.edu", mark: [#sym.dagger]),
  (name: "Michail Maniatakos", email: "mm4410@nyu.edu", mark: [#sym.dagger]),
)

#let affiliations = (
  (name: [New York University Abu Dhabi, Center for Cyber Security], mark: [#sym.dagger]),
)

#let review_id = [\#001]
#let ref_authors = if review_id == "none" { authors } else { ((name: "Anonymous Author(s)", email: "", mark: []),) }

#set page(
  // header-ascent: 20%,
  header: context {
    let page_num = counter(page).get().first()

    if page_num > 1 and calc.even(page_num) {
      grid(
        columns: (1fr, 1fr),
        align: (left, right),
        text(size: 7pt, title), text(size: 7pt, [#conference.short, #conference.year, #conference.venue]),
      )
    } else if page_num > 1 and calc.odd(page_num) {
      grid(
        columns: (1fr, 1fr),
        align: (left, right),
        text(size: 7pt, [#conference.short, #conference.year, #conference.venue]),
        text(size: 7pt, ref_authors.map(a => a.name).join(", ")),
      )
    }
  },
  footer: context {
    let current = counter(page).get().first()
    let total = counter(page).final().first()
    align(left, text(size: 9pt)[Page #current of 1 - #total])
  },
)

#show: acmart.with(
  title: title,
  authors: authors,
  affiliations: affiliations,
  conference: conference,
  doi: doi,
  copyright: "cc",
  review: review_id,
)

#let ccs = (
  (
    generic: [Software and its engineering],
    specific: ([Virtual machines], [Virtual memory]),
  ),
  (
    generic: [Computer systems organization],
    specific: ([Heterogeneous (hybrid) systems],),
  ),
)

#let keywords = (
  "Industrial Control Systems",
  "Generative Modeling",
  "Fuzzing",
  "Dataset Generation",
  "Protocol Emulation",
)

#let appendix(body) = {
  set heading(numbering: "A.1", supplement: [Appendix])
  counter(heading).update(0)
  body
}

= Abstract
#include "sections/abstract.typ"

#acmart-ccs(ccs)
#parbreak()
#acmart-keywords(keywords)
#acmart-ref(title, ref_authors, conference, doi)

= Introduction
#include "sections/introduction.typ"

= Methodology
#let data = csv("sections/inventory.csv")
#let body-rows = if data.len() > 1 { data.slice(1) } else { () }

#table(
  columns: 5,
  table.header(
    table.cell(colspan: 2, fill: gray.lighten(90%))[*Product Details*],
    table.cell(colspan: 2, fill: gray.lighten(90%))[*Inventory & Price*],
    table.cell(rowspan: 2, align: horizon)[*Region*],
    // Sub-headers
    [*Type*],
    [*Item*],
    [*Stock*],
    [*Price*],
  ),

  // Map each row array to a set of styled cells
  ..body-rows
    .map(row => (
      row.at(0), // Category
      [*#row.at(1)*], // Item (made bold via Typst code)
      row.at(2), // Stock
      "$" + row.at(3), // Price with symbol
      row.at(4), // Warehouse
    ))
    .flatten(),
  // Flatten turns the (5,5,5) arrays into one list of 15
)

#bibliography("references.bib", title: "References", style: "association-for-computing-machinery")

#show: appendix

= Open Science
We are committed to open science principles and will publicly release the datasets, code, and methodology associated with this work upon publication. The datasets will be made available in both binary preserving (hex/base64) and canonical textual (JSONL) formats to facilitate use by a wide range of machine learning models. The code for the #project.name pipeline, including the Loader, Seed Generator, Validator, Fuzzer, and dataset construction tools, will be released under an open source license to encourage adoption and further development by the research community. We believe that providing these resources will enable reproducible research, foster collaboration, and accelerate progress in the field of ICS protocol emulation and security analysis.
