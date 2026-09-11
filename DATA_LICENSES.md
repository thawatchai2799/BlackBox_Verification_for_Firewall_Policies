# Licences of the third-party data in this repository

The code in this repository is released under the MIT licence (see `LICENSE`).
**The real-world firewall rule sets used by `e7_realworld.py` are NOT covered by
that MIT licence.** They are third-party data, redistributed under the licences
stated below. Anyone reusing this repository must honour those licences
separately.

## Where the data comes from

`e7_realworld.py` carries an embedded archive that is extracted on first run to
`data/realworld/`. The files are iptables rule sets in the *simple-firewall
normal form* produced by the verified toolchain of Diekmann et al.:

* Toolchain and normal-form dumps — <https://github.com/diekmann/Iptables_Semantics>
  (Cornelius Diekmann; **BSD 2-Clause**; the file redistributed here as
  `LICENSE_Diekmann_BSD2` is the licence text of that repository)
* Raw `iptables-save` / `iptables -L -n -v` dumps the normal forms are derived
  from — <https://github.com/diekmann/net-network>
  (Chair for Network Architectures and Services, TUM, and contributors)

The raw dumps in `net-network` are **not** BSD. Per the `net-network` README,
the directories used here are licensed as follows.

| file in `data/realworld/` | upstream directory in `net-network` | licence |
|---|---|---|
| `TUM_2013_FWD_lower.txt`, `TUM_2014_FWD_lower.txt`, `TUM_2015_FWD_lower.txt`, `TUM_2015_FWD_upper.txt` | `configs_chair_for_Network_Architectures_and_Services` | CC BY-NC-SA 3.0 |
| `home_user_FWD_lower.txt`, `home_user_FWD_upper.txt` | `config_home_user` | CC BY-NC-SA 3.0 |
| `medium_company_FWD_lower.txt`, `medium_company_FWD_upper.txt` | `configs_medium-sized-company` | CC BY-NC-SA 3.0 |
| `sqrl_shorewall_FWD_lower.txt`, `sqrl_shorewall_FWD_upper.txt` | `configs_sqrl_shorewall` | CC BY-NC-SA 3.0 |
| `synology_INP_lower.txt` | `configs_synology_diskstation_ds414` | CC BY-NC-SA 3.0 |
| `ugent_INP_lower.txt`, `ugent_INP_upper.txt` | `configs_ugent` | CC BY-NC-SA 3.0 |
| `docker_topos_FWD_upper.txt` | `configs_corny_docker` | CC BY-NC-SA 4.0 |
| `sargon_INP_lower.txt`, `gopherproxy_INP_lower.txt` | (to be confirmed — see note) | see note |

**Note on `sargon` and `gopherproxy`.** These two files were taken from the
`Iptables_Semantics` examples and we have not been able to match them to a
directory in `net-network`. Until the upstream source is confirmed, treat them
as covered by the most restrictive licence above (CC BY-NC-SA 3.0) and credit
Diekmann et al.

## What this means in practice

* **Attribution (BY).** Any reuse of the rule sets must credit Cornelius
  Diekmann and the Chair for Network Architectures and Services, TUM, and link
  to the upstream repositories.
* **NonCommercial (NC).** The rule sets may not be used for commercial purposes.
  This restriction applies to the data only, not to the MIT-licensed code.
* **ShareAlike (SA).** Derivatives of the rule sets — including the normal-form
  dumps extracted to `data/realworld/` — must be distributed under the same
  CC BY-NC-SA terms. They are therefore **excluded from the MIT licence** of
  this repository.
* Results computed *from* the data (the CSV files in `results/`, the figures,
  and the tables in the manuscript) are facts and measurements, not
  reproductions of the rule sets, and are released with the rest of the
  repository.

## Full licence texts

* BSD 2-Clause (Diekmann, toolchain and normal forms): `LICENSE_Diekmann_BSD2`
* CC BY-NC-SA 3.0: <https://creativecommons.org/licenses/by-nc-sa/3.0/>
* CC BY-NC-SA 4.0: <https://creativecommons.org/licenses/by-nc-sa/4.0/>
