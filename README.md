# CTF-tutor

> Learn the vulnerability. Understand the exploit. Capture the flag.

CTF-tutor is a practical learning tool for working through Capture The Flag challenges.

Instead of focusing only on getting the flag, the project focuses on understanding **why a vulnerability exists, how to identify it, and how the exploit works**.

---

## What it does

CTF-tutor takes a challenge or collection of learning material and helps break it down into smaller concepts.

The current system focuses on:

* Challenge decomposition
* Concept identification
* Explanation of technical concepts
* Source/resource ingestion
* Retrieval of relevant information
* Difficulty/depth guidance
* Challenge-oriented learning
* Static analysis utilities
* Automated tests

---

## Supported / planned areas

### PWN / Binary Exploitation

* Stack-based buffer overflows
* Registers
* Calling conventions
* Memory layout
* Shellcode
* ROP
* ret2win
* ret2libc
* ASLR
* NX
* PIE
* Stack canaries

### Reverse Engineering

* Basic binary analysis
* Program flow
* Assembly concepts
* Functions
* Registers
* Strings
* Static analysis

### Web

* HTTP fundamentals
* Authentication
* JWT
* Injection concepts
* Web application vulnerabilities

### General CTF

* Linux
* Networking
* Cryptography
* Forensics
* Enumeration
* Basic exploitation methodology

---

# Project structure

```text
CTF-tutor/
│
├── data/
│   └── archive/
│
├── ingest_sources/
│   ├── github_ingest.py
│   └── youtube_ingest.py
│
├── tests/
│   ├── fakes.py
│   ├── test_depth_guide.py
│   ├── test_explainer.py
│   ├── test_ingest.py
│   ├── test_llm_client.py
│   ├── test_main.py
│   ├── test_retriever.py
│   └── test_synthesizer.py
│
├── tools/
│   └── static_analysis.py
│
├── decomposer.py
├── depth_guide.py
├── explainer.py
├── ingest.py
├── llm_client.py
├── main.py
├── retriever.py
├── schema.py
├── synthesizer.py
│
├── requirements.txt
└── README.md
```

---

# How it works

The basic workflow is:

```text
             CTF Challenge
                   │
                   ▼
            ┌─────────────┐
            │  Ingestion  │
            └──────┬──────┘
                   │
                   ▼
          ┌─────────────────┐
          │   Decomposer    │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │    Retriever    │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │    Explainer    │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │   Synthesizer   │
          └────────┬────────┘
                   │
                   ▼
             Tutor Response
```

The important part is not simply producing an answer.

The goal is to break down the problem into concepts that the learner can understand and use on the next challenge.

---

# Installation

Clone the repository:

```bash
git clone git@github.com:long835/CTF-tutor.git
cd CTF-tutor
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

Run:

```bash
python main.py
```

The exact interface may change while the project is being developed.

---

# Example

A learner encounters a stack-based buffer overflow.

Instead of jumping directly to:

```text
FLAG{...}
```

the tutor should guide the learner through questions such as:

```text
1. Where is user-controlled input stored?

2. How large is the buffer?

3. What happens when the input exceeds the buffer?

4. What value is overwritten?

5. How can the overwrite offset be determined?

6. Which memory protections are enabled?

7. What control-flow technique is appropriate?

8. How can the final payload be constructed?
```

The learner should understand the process rather than simply copy a solution.

---

# Development

Run the test suite with:

```bash
pytest
```

Individual tests can be run with:

```bash
pytest tests/test_explainer.py
```

or:

```bash
pytest tests/test_retriever.py
```

---

# Roadmap

## Current

* [x] Basic project structure
* [x] Challenge decomposition
* [x] Explanation pipeline
* [x] Retrieval system
* [x] Source ingestion
* [x] Difficulty/depth guidance
* [x] Tests
* [x] Static analysis utilities

## Next

* [ ] Better PWN challenge support
* [ ] More binary exploitation examples
* [ ] Interactive hints
* [ ] Improved challenge classification
* [ ] Better source indexing
* [ ] More reverse-engineering material
* [ ] More web exploitation material
* [ ] Cleaner CLI interface

## Later

* [ ] User learning progress
* [ ] Challenge history
* [ ] Personalized difficulty
* [ ] CTF platform integration
* [ ] More automated binary analysis
* [ ] Interactive learning paths

---

# Philosophy

CTF-tutor is built around a simple idea:

> **Don't just solve the challenge. Understand why the solution works.**

A good CTF tool should help someone become less dependent on the tool over time.

---

# Contributing

Contributions are welcome.

Some useful areas for contribution:

* CTF examples
* PWN explanations
* Reverse-engineering material
* Web security material
* Tests
* Bug fixes
* Documentation
* Static-analysis utilities

If you find a problem, open an issue with enough information to reproduce it.

---

# Disclaimer

This project is intended for **education, CTF competitions, security research, and authorized testing**.

Only use exploitation techniques against systems you own or have explicit permission to test.

---

## Status

This project is currently under active development.

Expect things to change.
