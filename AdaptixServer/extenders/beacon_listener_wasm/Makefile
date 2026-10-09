all: clean
	@ echo "    * Building listener_beacon_wasm plugin"
	@ mkdir dist
	@ cp config.yaml ax_config.axs ./dist/
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/listener_beacon_wasm.so pl_main.go pl_transport.go
	@ echo "      done..."

clean:
	@ rm -rf dist
