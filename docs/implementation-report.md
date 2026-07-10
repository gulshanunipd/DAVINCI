# D4: Implementation Report of the DAVINCI Framework

DAVINCI: Deep Attestation Framework for Virtualized Network Communication Integrity

## About this document

This report explains how to set up, build, and run the DAVINCI prototype, and how to read the results it produces. It follows the design given in D3 and implements the attestation scheme and security properties defined in D2. Where D3 describes what each component should do, this document shows the concrete commands that get it running on a real machine and a worked example that exercises the full workflow.

The document has four parts:

1. Setting up the environment where DAVINCI runs, either in a virtual machine using Vagrant and Ansible, or directly on your own computer.
2. Setting up DAVINCI itself, meaning the key material and the build of the three services.
3. Running an example instance of DAVINCI from start to finish.
4. Reading the output of that example, together with the current limitations of the prototype.

The prototype is made of three services written in Rust and a small set of Python scripts that act as evidence sources for the demonstration.

* The Privacy Control Engine runs on port 3032. It applies the privacy transformations to evidence.
* The Attestation Manager runs on port 3030. It checks each piece of evidence, builds the measurement chain and the trust graph, and exports a signed result.
* The Verifier runs on port 3031. It checks the signed result and produces the trust decision.

All signatures use ECDSA over the NIST P256 curve, and all hashing uses SHA-256, which are the cryptographic primitives assumed in D2.

## Part 1: Setting up the environment

There are two supported ways to prepare a machine. The first uses a virtual machine and is the most reproducible, because every dependency is installed the same way every time. The second installs the same dependencies directly on macOS or Linux, which is convenient if you already work on the machine day to day.

### Option A: A virtual machine with Vagrant and Ansible

This option builds a clean Ubuntu 22.04 virtual machine and provisions it automatically. You need VirtualBox and Vagrant installed on your host. On macOS you can install both with Homebrew:

```
brew install --cask virtualbox
brew install --cask vagrant
```

On a Debian or Ubuntu host you can install them with apt:

```
sudo apt update
sudo apt install -y virtualbox vagrant
```

The repository already contains a Vagrantfile and an Ansible playbook at provisioning/playbook.yml. From the root of the DAVINCI directory, create and provision the machine with a single command:

```
vagrant up
```

This downloads the Ubuntu image, boots the machine, and then runs the Ansible playbook inside it. The playbook installs the build tools and the OpenSSL development libraries, installs the Rust toolchain, installs Python, generates the DAVINCI keys, and builds the three services. The three service ports 3030, 3031, and 3032 are forwarded to the same ports on your host, so you can reach the services from your own terminal.

When provisioning finishes, log in to the machine and move to the project directory, which is mounted inside the machine at /vagrant:

```
vagrant ssh
cd /vagrant
```

You are now ready for Part 3. If you want to provision again without rebuilding the machine, run vagrant provision. To shut the machine down, run vagrant halt, and to delete it completely, run vagrant destroy.

If you prefer to run the same playbook against a plain Ubuntu host instead of a virtual machine, install Ansible and run it in local mode from the project directory:

```
sudo apt install -y ansible
ansible-playbook -i "localhost," -c local provisioning/playbook.yml
```

### Option B: Setting up directly on macOS or Linux

If you would rather run everything on your own machine, install four things: the Rust toolchain, OpenSSL, pkg-config, and Python 3. DAVINCI has been developed and tested on macOS with these tools, and the same steps work on Linux with apt.

Install the Rust toolchain through rustup, which does not require administrator rights:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

On macOS, install OpenSSL and pkg-config with Homebrew, then point pkg-config at the OpenSSL you just installed so that the Rust build can find it:

```
brew install openssl@3 pkg-config
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
```

On Ubuntu or Debian, install the equivalent packages with apt:

```
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev openssl python3
```

Python 3 is already present on macOS and on most Linux systems. The demonstration scripts use only the Python standard library and the openssl command line tool, so there are no extra Python packages to install.

You can confirm the toolchain is ready with:

```
rustc --version
openssl version
python3 --version
```

## Part 2: Setting up DAVINCI

With the environment in place, move to the root of the DAVINCI directory. On the developer machine this is:

```
cd /Users/himanshudevgan/Documents/gulshan/DAV-main
```

Inside the virtual machine it is /vagrant. The layout of the directory is as follows. The attestation-manager, verifier, and pce-service folders each hold one Rust service. The keys folder holds the key material. The demo folder holds the example scripts. The docs folder holds the design and implementation reports.

### Generating the keys

DAVINCI relies on two kinds of keys. The Attestation Manager has its own key pair. It signs its results with the private key, and the Verifier trusts the matching public key, which plays the role of the trust anchor in D2 and D3. There is also one key pair for each Root of Trust source, such as the TPM and the confidential computing report. In a real deployment these would be hardware protected keys inside the attestation hardware. In the prototype they are software keys that stand in for that hardware, so that the signature checks are genuine even without special hardware.

Generate all of the keys with the helper script:

```
./keys/gen-keys.sh
```

This writes the Attestation Manager key pair and the per source key pairs into the keys folder. The private keys are never committed to version control, so this step must be run once on any fresh copy of the repository.

### Building the services

The simplest path is the Makefile target that generates the keys and then builds all three services:

```
make build
```

On macOS, remember to export PKG_CONFIG_PATH first, as shown in Part 1, so that the OpenSSL library is found during the build. The first build downloads and compiles the dependencies and can take a few minutes. Later builds are fast.

If you prefer to build the services one at a time, you can build each crate on its own:

```
cd pce-service && cargo build && cd ..
cd attestation-manager && cargo build && cd ..
cd verifier && cargo build && cd ..
```

### Configuration

The services read a few settings from environment variables. The defaults are chosen so that everything works on one machine without any configuration, so you can usually ignore this section for a first run.

* DAVINCI_KEYS_DIR is the folder that holds the keys. It defaults to ../keys, which is correct when a service is started from its own crate folder.
* PCE_URL tells the Attestation Manager where to reach the Privacy Control Engine. It defaults to http://localhost:3032.
* ATTESTATION_MANAGER_URL tells the Verifier where to reach the Attestation Manager. It defaults to http://localhost:3030.
* DATABASE_URL tells the Privacy Control Engine to use a PostgreSQL database. If it is not set, the engine keeps its data in memory, which is fine for the example.
* AM_BIND, VERIFIER_BIND, and PCE_BIND set the address each service listens on. They default to all interfaces on the service port.

## Part 3: Running an example instance

The example drives the whole workflow. It sends platform, hypervisor, guest, and runtime evidence to the Attestation Manager, asks the Verifier for a decision, and prints the result. It runs two scenarios back to back. The first uses authentic evidence and should be trusted. The second tampers with the guest evidence after the Root of Trust has signed it, and should be rejected.

### Start the services

Start the three services in the correct order. Start the Privacy Control Engine first, because the Attestation Manager depends on it. Give each service its own terminal, because each one runs in the foreground and prints a log.

In the first terminal:

```
make run-pce
```

It prints that it is listening on port 3032 and whether it is using a database or in memory storage.

In the second terminal:

```
make run-attestation-manager
```

It prints that it is listening on port 3030, the address of the Privacy Control Engine, and how many Root of Trust keys it loaded.

In the third terminal:

```
make run-verifier
```

It prints that it is listening on port 3031 and the address of the Attestation Manager.

You can confirm that all three are up with three quick requests:

```
curl -s http://127.0.0.1:3032/health
curl -s http://127.0.0.1:3030/pubkey
curl -s http://127.0.0.1:3031/health
```

The first returns a status of ok, the second returns the Attestation Manager public key in PEM form, and the third returns a status of ok.

### Run the example

In a fourth terminal, move to the demo folder and run the comparison example, which runs the trusted scenario and then the tampered scenario:

```
cd demo
python3 demo_comparison.py
```

There is also a single end to end run that only performs the trusted scenario:

```
python3 demo_scenario.py
```

The same runs are available through the Makefile as make demo-compare and make demo.

## Part 4: Reading the output and current limitations

### What the trusted scenario prints

In the trusted scenario every layer sends authentic evidence, so the Attestation Manager admits each item, builds the graph, and signs it. The Verifier then confirms every check and returns a trusted decision:

```
Trust Decision: TRUSTED
Checks:
  PASS Output Signature (ECDSA-P256)
  PASS Freshness (challenge binding)
  PASS Platform Root Present
  PASS Edge Signatures (ECDSA-P256)
  PASS Layer Monotonicity
  PASS Binding Policy
  PASS Acyclicity
  PASS Cross-Layer Trust Continuity
```

### What the tampered scenario prints

In the tampered scenario the guest measurement is changed after the Root of Trust signed it. The Attestation Manager checks the signature over the guest measurement, finds that it no longer matches, and rejects that evidence. The guest node therefore never enters the graph. The runtime node above it then has no path down to the platform, so the Verifier reports that the cross layer trust continuity check has failed and returns a not trusted decision:

```
3. Guest SEV-SNP evidence ...  (TAMPERED after RoT signature)
   AM: rejected_auth: RoT signature invalid, evidence not authentic (Auth = 0)

Trust Decision: NOT TRUSTED
  PASS Output Signature (ECDSA-P256)
  PASS Freshness (challenge binding)
  PASS Platform Root Present
  PASS Edge Signatures (ECDSA-P256)
  PASS Layer Monotonicity
  PASS Binding Policy
  PASS Acyclicity
  FAIL Cross-Layer Trust Continuity  (Application-layer node has no trust path to Platform)
```

The important point is that this decision comes from real signature checks and graph checks, not from any label attached to the session.

### The signed output and the trust graph

The Attestation Manager exports the result at GET /attest/output/{session}?nonce={challenge}. The response contains the output and a proof, which is the Attestation Manager signature over that output. A trimmed example looks like this:

```
{
  "out": {
    "sid": "d4_example_1783669785",
    "challenge": "chal_demo_0001",
    "ts_out": 1783669785,
    "manifest": { "redacted": 8, "aggregated": 0, "retained": 1 }
  },
  "pf": "304602210082649319d58a1a7ae4d97faa074fe3cefd343c..."
}
```

The manifest records what the Privacy Control Engine did to the evidence. In this run it removed eight sensitive fields across the four evidence items, which is the host name and the address field of each item, and kept the fields that verification needs.

Each node in the graph carries its profile, its measurement, its position in the hash chain, and its hash. One node looks like this:

```
{
  "jti": "645f3ed0-e43c-4334-a3e0-4f8c0182dd5d",
  "eat_profile": "layer:Application,mode:Runtime,source:Ima",
  "eat_meas": "{\"claims\":{},\"measurement\":\"bf1f8f7c3bba11c48e9c...\"}",
  "iat": 1783669785,
  "x_davinci_prev": "f792985febed579dd70c0e110474e59268dedc84717a19255fa9ea9496e93859",
  "hash": "f9a9e69f02e52dcbf3ba7c54b5c341983aa0c3fadbe23e64ae2b3bebf5e980ef"
}
```

Each edge records a trust dependency and carries the Attestation Manager signature over that edge. One edge looks like this:

```
{
  "from": "4165ca62-aa7b-46c8-ae29-5fe7566a7e65",
  "to": "5bec0611-88bf-4992-8ca7-a3e492f3c2c2",
  "relationship": "VmIncludesHypervisor",
  "signature": "30440220429844689d9cf0dfda5a918ebb3592e794a1c929..."
}
```

### How the checks map to the security properties

Each check the Verifier performs corresponds to a property defined in D2.

* Output Signature and Edge Signatures give authenticity, because only the holder of the Attestation Manager private key can produce them.
* Freshness gives replay resistance, because the Verifier binds a fresh challenge into every request and confirms the same challenge is present in the signed output.
* Platform Root Present, Layer Monotonicity, Acyclicity, Binding Policy, and Cross-Layer Trust Continuity together give deep integrity and cross layer trust continuity, because they confirm that every attested layer has a signed and well formed path down to the hardware anchored platform.
* The rejection of tampered evidence at the Attestation Manager, before it ever reaches the graph, gives the evidence authenticity that underlies multi modal soundness.
* The Privacy Control Engine gives the privacy properties, because it pseudonymises stable identifiers and removes sensitive fields before the evidence is stored or exported.

### The APIs

The Attestation Manager accepts boot evidence at POST /attest/boot and runtime evidence at POST /attest/runtime. It returns the signed output at GET /attest/output/{session}, the raw graph for inspection at GET /arg/{session}, and its public key at GET /pubkey. The Verifier accepts a request at POST /verify with a session and a challenge and returns the full decision with the per check details. The Privacy Control Engine accepts POST /privacy/transform, POST /validate/node, and POST /resolve/pseudonym, and reports its state at GET /health.

### Current limitations

The prototype is faithful to the design in the parts it implements. The following points describe what it does not yet do, so that results are read correctly.

First, the hardware Roots of Trust are simulated. The evidence is signed with software ECDSA keys that stand in for hardware protected keys, so the signature checks are real, but no physical TPM or confidential computing hardware is involved.

Second, the bootstrap attestation of the Attestation Manager host, described in D3, is not implemented. The Verifier trusts the Attestation Manager public key from its key folder rather than first appraising the host that holds it.

Third, the Verifier validates the graph it receives, but it does not yet require a fixed set of layers to be present. A result that contains a smaller but internally valid graph is accepted as far as it goes. Enforcing a required set of layers per session is the natural next step and follows directly from the session policy described in D3.

### Stopping the services

Each service runs in the foreground, so stopping it is a matter of pressing Ctrl and C in its terminal. If you started the services in the background, you can stop them by name:

```
pkill -f target/debug/pce-service
pkill -f target/debug/attestation-manager
pkill -f target/debug/verifier
```
