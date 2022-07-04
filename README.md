# Kampai

| **Kampai is a proof of concept, and is alphaware. Proceed at your own caution.** |
| - |

Kampai is a method of full-duplex, end-to-end encrypted, peer-to-peer secure communications.

## Quickstart

1. **Install Kampai**

   You will need minimally Python 3.7 or newer.

   ```text
   pip install kampai
   ```

   _Alternatively, you can just clone the repository and run `python kampai.py`. The only
   dependency Kampai has is [PyNaCl](https://github.com/pyca/pynacl/). See the dependency
   requirement in the `pyproject.toml` file._

2. **Figure out Port Forwarding**

   Kampai is a method, not a service. This means you will have to find a way to expose
   your localhost UDP ports to your contact. Consider checking out
   [anderspitman/awesome-tunneling](https://github.com/anderspitman/awesome-tunneling).

3. **Using Kampai**

   Starting a Kampai session

   ```
   kampai  # equivalent to: kampai create --client_host 127.0.0.1 --client_port 450000
   ```

   Joining a Kampai session

   ```
   kampai join 127.0.0.2
   ```

   For more information, run `kampai --help`.

## License

Kampai is free and unencumbered software released into the public domain. For more
information, please refer to <http://unlicense.org/> or the kampai module docstring.
