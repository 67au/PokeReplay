# POKE-REPLAY

## USAGE

Install Deps

```shell
pip install httpx
```

Edit Configure file, and Save it as `config.toml`

```toml
[from_server]
api_url = ""
username = ""
password = ""
origin = ""
referer = ""

[to_server]
api_url = ""
username = ""
password = ""
origin = ""
referer = ""
```

Then, run

```shell
python replay.py --config config.toml
```

As the result, Console return something like

```shell
Copy [username](https://api_url) => [username](https://api_url)
Status: Finish
```

## Advanced Usage

If you load a existed json (such as `dump.json`), please keep `[from_server]` empty and run

```shell
python replay.py --config config.toml --load dump.json
```

If you dump json from api server, run

```shell
python replay.py --config config.toml --dump dump.json
```

## LICENSE

MIT License
