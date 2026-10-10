```sh
sh <<'INSTALL'
set -eu

# 检查管理员权限
run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    echo "请以 root 身份运行，或先安装 sudo。" >&2
    exit 1
fi

# 自动安装依赖
if command -v apk >/dev/null 2>&1; then
    run_as_root apk add --no-cache python3 curl ca-certificates
elif command -v apt-get >/dev/null 2>&1; then
    run_as_root apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive \
        apt-get install -y python3 curl ca-certificates
elif command -v dnf >/dev/null 2>&1; then
    run_as_root dnf install -y python3 curl ca-certificates
else
    echo "自动安装支持 Alpine、Debian、Ubuntu 及使用 dnf 的系统。" >&2
    exit 1
fi

# 下载脚本；退出时清理临时文件
script=$(mktemp)
trap 'rm -f "$script"' EXIT

curl -fsSL \
    https://raw.githubusercontent.com/imNebula/lazycat_dns/main/encrypt-proxy-dns.sh \
    -o "$script"

# 自动处理配置并重启对应服务
run_as_root sh "$script"
INSTALL
```
