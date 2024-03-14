# Interop Tests
## Goal
The goal of the tests in this category is to test interoperability with other TLS implementations. 

## Why Another Framework
> s2n-tls already has unit tests, integration tests, and _more_ integration tests in the rust bindings? Why is it necessary to write new ones?

Well it's true that our existing test frameworks are capable of reproducing and asserting on most issues, the goal is to find issues before we are aware of them. Our existing integration tests have some very limiting and specific assumptions that are not found in existing applications.

Our [integrationv2](../integrationv2/README.md)
