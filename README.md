# Secure Authentication Extension
This repository contains the source code of my Master Thesis "Secure &amp; Privacy-Preserving Two Factor Authentication on a Programmable Security Key" at the University of St. Gallen.

## Checking out the code

``` 
git clone https://github.com/yasmineantille/secure-authentication-extension
git submodule init
```

or 

```
git clone --recurse-submodules https://github.com/yasmineantille/secure-authentication-extension
```

## Installation
```
pip install -r requirements.txt
```

## Proof of Correctness
A python prototype was implemented to verify the validity of the proposed scheme, offering a functional representation of the core protocol. 

Run the code by calling ```python poc/poc.py```