#import "@preview/fletcher:0.5.5" as fletcher: diagram, edge, node

// --- Helper Functions ---
#let blackcircle(text_content) = {
  box(
    align(center + horizon)[
      #place(center + horizon, circle(radius: 8pt, fill: black))
      #place(center + horizon, text(fill: white, weight: "bold", size: 8pt)[#text_content])
    ],
    width: 16pt,
    height: 16pt,
  )
}

// --- Style Definitions ---
#let main-node = (
  shape: rect,
  width: 2.5cm,
  height: 1cm,
  stroke: 1pt + black,
  inset: 5pt,
)

#let io-node = (
  shape: fletcher.shapes.parallelogram,
  width: 2.5cm,
  height: 0.8cm,
  stroke: 1pt + black,
  inset: 5pt,
)

#let db-node = (
  shape: rect,
  width: 1.5cm,
  height: 2cm,
  stroke: 1pt + black,
)

// --- The Diagram Definition ---
#let pipeline_diagram = diagram(
  node-stroke: 1pt,
  spacing: (1.5cm, 1.5cm), // Grid spacing
  node-defocus: 0,

  // 1. Seed Generator Group (Encloses Cols 1 & 2)
  node(
    (1.5, 0.5), // Centered roughly between the nodes
    width: 13em,
    height: 7em,
    fill: gray.lighten(90%),
    stroke: (dash: "dashed", paint: gray),
    shape: rect,
    layer: -1, // Send to back
    name: <seed_gen_group>,
    inset: 10pt,
    [Seed Generation],
  ),

  // 2. Fuzzing Engine Group (Encloses Col 3, Rows 2 & 3)
  node(
    (3, 2.5),
    width: 7em,
    height: 8em,
    fill: blue.lighten(95%),
    stroke: (dash: "dashed", paint: blue),
    shape: rect,
    layer: -1,
    name: <fuzz_engine_group>,
    // align: top,
    inset: 10pt,
    [Fuzzing Engine],
  ),

  // --- Nodes ---
  // Col 0
  node((0, 0), ..main-node, fill: orange.lighten(80%), [loader], name: <loader>),
  node((0, 2), ..io-node, fill: blue.lighten(80%), [config], name: <config>),
  node((0, 3), ..io-node, fill: yellow.lighten(80%), [prompt], name: <prompt>),

  // Col 1
  node((1, 0), ..main-node, fill: orange.lighten(80%), [generator], name: <generator>),
  node((1, 1), ..main-node, fill: orange.lighten(80%), [validator], name: <validator>),

  // Col 2
  node((2, 1), ..main-node, fill: red.lighten(50%), [plc], name: <plc>),

  // Col 3
  node((3, 2), ..db-node, fill: gray.lighten(80%), [corpus], name: <corpus>),
  node((3, 3), ..main-node, fill: orange.lighten(80%), [fuzzer], name: <fuzzer>),

  // Col 4
  node((4, 2.5), ..db-node, fill: green.lighten(80%), [dataset], name: <dataset>),

  // --- Edges ---
  edge(<prompt>, <config>, "-|>", label: blackcircle("h1"), label-pos: 0.5, label-side: left),
  edge(<config>, <loader>, "-|>", label: blackcircle("h2"), label-pos: 0.5, label-side: left),
  edge(<loader>, <generator>, "-|>", label: blackcircle("h3"), label-pos: 0.25, label-side: center),
  edge(<generator>, <validator>, "-|>", label: blackcircle("h4"), label-side: right),

  edge(<validator>, <plc>, "-|>", bend: 35deg, label: "Request", label-side: center),
  edge(<plc>, <validator>, "-|>", bend: 35deg, label: "Response", label-side: center),

  edge(<fuzzer>, <plc>, "-|>", bend: 35deg, label: "Request", label-side: center),
  edge(<plc>, <fuzzer>, "-|>", bend: 35deg, label: [Response #blackcircle("h8")], label-side: center),

  // Shifted edges for Corpus <-> Fuzzer loop
  edge(<corpus>, <fuzzer>, "-|>", shift: -10pt, label: [Pick Seed #blackcircle("h6")], label-side: left),
  edge(<fuzzer>, <corpus>, "-|>", shift: -10pt, label: [Enrich #blackcircle("h7")], label-side: right),

  edge(<generator>, <corpus>, "-|>", label: [Initial Seeds\ #blackcircle("h5")], label-pos: 0.5),

  // Edge from the group itself
  edge(<fuzz_engine_group>, <dataset>, "-|>", label: blackcircle("h9")),
)
