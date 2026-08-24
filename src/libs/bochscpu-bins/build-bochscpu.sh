# Axel '0vercl0k' Souchet - May 2 2020
# Build / configure bxcpu-ffi
pushd .

mkdir bxbuild-unix
cd bxbuild-unix

git clone https://github.com/yrp604/bochscpu-build.git
git clone https://github.com/yrp604/bochscpu
git clone https://github.com/yrp604/bochscpu-ffi

if [ "$(uname)" = "Darwin" ]; then
    export MACOSX_DEPLOYMENT_TARGET="$(sw_vers -productVersion)"
fi

cd bochscpu-build
git checkout tags/v0.6
BOCHS_REV=$(cat BOCHS_REV) bash prep.sh && cd Bochs/bochs && sh .conf.cpu && make cpu/libcpu.a cpu/fpu/libfpu.a cpu/avx/libavx.a cpu/cpudb/libcpudb.a cpu/softfloat3e/libsoftfloat.a

# Remove old files in bochscpu.
rm -rf ../../../bochscpu/bochs
rm -rf ../../../bochscpu/lib

# Create the libs directory where we stuff all the libs.
mkdir ../../../bochscpu/lib
cp cpu/libcpu.a ../../../bochscpu/lib/libcpu.a
cp cpu/fpu/libfpu.a ../../../bochscpu/lib/libfpu.a
cp cpu/avx/libavx.a ../../../bochscpu/lib/libavx.a
cp cpu/cpudb/libcpudb.a ../../../bochscpu/lib/libcpudb.a
cp cpu/softfloat3e/libsoftfloat.a ../../../bochscpu/lib/libsoftfloat.a
make all-clean

# Now we want to copy the bochs directory over there.
cd ..
mv bochs ../../bochscpu/bochs

# Now its time to build it  (`RUSTFLAGS` to build a static version, otherwise the Windows `.lib`'s size is blowing up (64mb+))..
cd ../../bochscpu-ffi

export RUSTFLAGS="-C target-feature=+crt-static"
cargo clean
case "$(uname)" in
    Linux)
        # Why do we need this `--target`? Well I'm not sure.. but https://github.com/rust-lang/rust/issues/78210 :(
	cargo build --release --target $(uname -m)-unknown-linux-gnu ;;
    Darwin)
        # macOS (arm64) works without --target.
        cargo build --release ;;
    *)
        echo "Unsupported platform: $(uname)" >&2; exit 1 ;;
esac

# Get back to where we were.
popd
