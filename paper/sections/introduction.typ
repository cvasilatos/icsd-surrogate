#import "../assets/high_level_pipeline.typ": pipeline_diagram
#import "table.typ": comparison-table
#let project = json("../resources/metadata.json")

#let blackcircle(text_content) = {
  box(
    align(bottom)[
      #place(bottom, circle(radius: 5pt, fill: black))
      #place(right, text(fill: white, weight: "bold", size: 7pt)[#text_content])
    ],
    width: 8pt,
    height: 8pt,
  )
}

Industrial control systems form the backbone of critical infrastructure spanning energy grids, water treatment facilities, manufacturing plants, transportation networks, and utilities @7434576. These systems orchestrate physical processes through programmable logic controllers, supervisory control and data acquisition (SCADA) systems, and field devices that communicate using specialized industrial protocols. The increasing connectivity and digitization of ICS have dramatically expanded their attack surface, exposing critical infrastructure to cyber threats with potentially catastrophic consequences ranging from service disruptions to physical damage @7434576 @cook2016measuring.

Despite the critical importance of ICS security, research and development are severely hampered by the scarcity of accessible hardware, proprietary protocols, and safety constraints that prevent experimentation on operational systems. This has motivated efforts to develop virtual environments, simulators, and emulators that can faithfully reproduce ICS behavior for testing, training, and security research @iqbal2015environment @satria2009vdees @sampath2011efficient @dehlaghi2023icssim. Virtual development environments enable software testing without physical hardware @satria2009vdees @sampath2011efficient, while comprehensive testbed frameworks like ICSSIM @dehlaghi2023icssim provide realistic settings for security evaluation. However, these simulation approaches often require extensive domain knowledge, manual configuration, and access to reference implementations or detailed protocol specifications.

The machine learning community has increasingly turned to ICS datasets to develop intelligent security solutions, but the available corpora exhibit significant limitations. Existing publicly available datasets predominantly focus on intrusion detection and anomaly classification @morris2014industrial @dehlaghi2023anomaly, providing labeled network traffic captures designed to distinguish normal from malicious behavior. While valuable for training defensive systems, these datasets lack the structured request-response (R/R) pairs necessary for generative modeling tasks. Morris and Gao's industrial control system traffic datasets @morris2014industrial established early benchmarks for intrusion detection research, and more recent efforts like the anomaly detection dataset by Dehlaghi et al. @dehlaghi2023anomaly provide labeled samples for classification. However, neither provides the clean input–output pairs required to train sequence to sequence models that can synthesize protocol compliant responses.

#figure(
  pipeline_diagram,
  caption: [High-level overview of the #project.name pipeline illustrating the seed generation and fuzzing components. The Loader ingests the LLM-generated protocol specification, the Seed Generator produces initial valid requests, the Validator checks the generated requests for correctness and enriches with responses, and the Fuzzer iteratively mutates requests to explore protocol behavior, storing interesting request/response pairs in the Dataset for dataset construction.],
  placement: top,
  scope: "parent",
) <fig-pipeline>


Recent work has begun exploring generative approaches for ICS protocol data. Yang et al. @yang2024novel proposed using generative adversarial networks (GANs) to generate fuzzing test cases for industrial protocols, while Zarzycki et al. @zarzycki2023gan investigated GAN architectures for testing process control networks against cyber attacks. Despite these promising directions, no prior work has released a standardized, ML ready corpus of paired protocol request–response exchanges suitable for supervised training and rigorous evaluation of generative models. This absence of a benchmark dataset hinders fair comparison across approaches, prevents reproducible research, and limits the development of practical protocol emulation systems.

The gap between classification oriented datasets and the needs of generative modeling is particularly acute. Training models to emulate protocol behavior, generating correct responses given arbitrary requests, requires clean, protocol faithful R/R pairs that capture the deterministic logic of industrial devices. Such models have applications beyond security, including software testing @iqbal2015environment @satria2009vdees, interoperability validation, honeypot development @vasilatos2025llmpot, and training environments where access to physical hardware is constrained. Yet researchers currently lack access to standardized corpora that would enable systematic investigation of generative techniques for ICS protocol emulation.

This paper introduces #project.name, a novel fuzzing based methodology to ondemand generate curated request-response pairs for representative ICS protocols, we explicitly created datasets using our framework for Modbus, S7comm and DNP3, nevertheless the framework can be used for additional ones without manual intervention. The datasets are explicitly designed for generative modeling. Our framework repurposes the ideas and notions used in fuzzing to explore valid requests against a ICS device that communicates using a TCP protocol. We provide two interoperable serializations binary preserving (hex/base64) for byte level models and canonical textual JSONL for tokenizer friendly training and frame the benchmark around response synthesis: given a request, produce a protocol conformant response. Informed by dataset quality principles for machine learning @gupta2021data  @ding2018approach @gong2023survey, we provide validation tools to ensure ML suitability.

*High Level Pipeline*: @fig-pipeline presents an overview of the #project.name pipeline. The process begins with an LLM prompt that yields a protocol specification #blackcircle("h1"), which is then materialized as a JSON protocol specification #blackcircle("h2") and ingested by the Loader. The Loader parses the specification as described in detail in Section~\ref{sec:seed_generation} before passing it to the Seed Generator #blackcircle("h3"), which produces an initial set of valid protocol requests #blackcircle("h4"). These requests are forwarded to the Validator, which interacts with a real ICS device (PLC) to obtain responses and ensure request-response correctness #blackcircle("h8"). The resulting initial seeds are then transferred to the seed corpus #blackcircle("h5"). During fuzzing, the Fuzzer picks seeds from the corpus #blackcircle("h6"), sends mutated requests to the PLC, collects responses #blackcircle("h8"), and adds interesting new packets back into the seed corpus #blackcircle("h7"). Finally, the fuzzing engine exports the accumulated request-response pairs into the Dataset #blackcircle("h9") for training and evaluation of generative models.

The *main contributions* of this paper are:
- A novel fuzzing based methodology to systematically generate high quality request–response pairs for potentially any ICS protocol, ensuring protocol compliance and diversity.
- Standardized corpus of request–response pairs for Modbus/TCP, S7comm, and DNP3, released in binary preserving and canonical textual forms for generative modeling.
- Quantify quality of the dataset using established data quality metrics for machine learning datasets to ensure its suitability for training robust models.
- Test resulting datasets with multiple baseline models including byte-level sequence models and tokenizer-friendly language models.
- Publicly release the datasets and methodology at: https://anonymous.4open.science/r/icsclone/

#figure(
  comparison-table,
  caption: [Comparison of throughput and latency.],
) <tab:comparison>
