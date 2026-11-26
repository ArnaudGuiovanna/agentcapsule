#!/bin/sh
# Called by Dagger in an isolated Ubuntu build stage.
set -eu
gpg --batch --no-options --dearmor --output ffmpeg-release.gpg ffmpeg-devel.asc
gpgv --keyring "$PWD/ffmpeg-release.gpg" ffmpeg-9.1.tar.xz.asc ffmpeg-9.1.tar.xz
tar xf ffmpeg-9.1.tar.xz
cd ffmpeg-9.1
# Keep input demuxers, parsers and decoders. Conversion emits MP3 audio
# segments and JPEG keyframes. All input is read locally inside the guest.
./configure --prefix=/usr --disable-debug --disable-doc --disable-network \
    --disable-autodetect --disable-ffplay --disable-avdevice \
    --enable-libmp3lame --enable-libdav1d --enable-libopus --enable-zlib --enable-lzma --enable-bzlib \
    --disable-encoders --enable-encoder=libmp3lame,mjpeg \
    --disable-muxers --enable-muxer=mp3,image2 \
    --disable-filters --enable-filter=select,scale,format,aformat,aresample,trim,atrim,null,anull,setpts,asetpts
make -j6 ffmpeg ffprobe
package=/build/package
doc="$package/usr/share/doc/ffmpeg"
install -d "$package/DEBIAN" "$package/usr/bin" "$doc"
install -m 0755 ffmpeg ffprobe "$package/usr/bin/"
install -m 0644 COPYING.LGPLv2.1 "$doc/copyright"
install -m 0644 ../ffmpeg-9.1.tar.xz ../ffmpeg-9.1.tar.xz.asc ../build-ffmpeg.sh "$doc/"
./ffmpeg -hide_banner -buildconf > "$doc/build-options.txt" 2>&1
cat > "$package/DEBIAN/control" <<'EOF'
Package: ffmpeg
Version: 7:9.1-0agentcapsule1
Architecture: amd64
Maintainer: AgentCapsule contributors
Homepage: https://ffmpeg.org/
Depends: libc6, libmp3lame0, libdav1d7, libopus0, zlib1g, liblzma5, libbz2-1.0
Description: FFmpeg upstream 9.1 with local-file codecs for AgentCapsule.
EOF
dpkg-deb --root-owner-group --build "$package" /build/ffmpeg.deb
