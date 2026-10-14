# Third-party licences

Easy Radius is a single-tenant tool. These are the Python packages it installs, and the licences they use. Version pins are in `requirements.txt` and `requirements-dev.txt`.

| Package | Role | Licence |
| --- | --- | --- |
| Flask | Web pages | BSD-3-Clause |
| Werkzeug | Flask dependency | BSD-3-Clause |
| Jinja2 | Flask templates | BSD-3-Clause |
| MarkupSafe | Jinja2 dependency | BSD-3-Clause |
| ItsDangerous | Flask sessions | BSD-3-Clause |
| Click | Flask dependency | BSD-3-Clause |
| Blinker | Flask dependency | MIT |
| cryptography | Encrypted backups and the automation password | Apache-2.0 or BSD-3-Clause |
| cffi | cryptography dependency | MIT |
| pycparser | cffi dependency | BSD-3-Clause |
| librouteros | RouterOS API | GPL-2.0-only |
| PyYAML | Task files | MIT |
| pytest | Tests only | MIT |
| pluggy | pytest dependency | MIT |
| iniconfig | pytest dependency | MIT |
| packaging | pytest dependency | Apache-2.0 or BSD-2-Clause |
| Pygments | pytest dependency | BSD-2-Clause |

librouteros is GPL-2.0-only. Shipping Easy Radius together with that library means the combined program has to follow GPL-2.0 when you distribute it. The other runtime libraries use permissive licences.

RouterOS itself is not included. MikroTik's software stays on the routers.
