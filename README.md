# fayawall

## Running

With Docker running, build the image:

```sh
docker build -t "fayawall" .
```

Run a container with extended privileges:

```sh
docker run -it --privileged fayawall
```

Then start `fayawall` with `cargo`:

```sh
cargo run
```
