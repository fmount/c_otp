# Maintainer: Francesco Pantano <fmount9@autistici.org>
# Contributor: fmount

pkgname=('c_otp')
_pkgname="c_otp"
packager="fmount"
pkgver="1.0"
pkgrel=1
bindir=usr/bin
pkgdesc="HOTP / TOTP pure C implementation"
url="htps://github.com/fmount/${pkgname}.git"
arch=('i686' 'x86_64')
license=('MIT')
depends=('openssl')
source=("git://github.com/fmount/${pkgname}.git")
md5sums=('SKIP')

#pkgver() {
#    cd $_pkgname
#    #git describe --tags |sed 's/-/./g'
#}

prepare() {
    cd "$_pkgname" || exit -1
}

build() {
  echo "Start building $_pkgname"
  cd "${srcdir}/$_pkgname" || exit -1
  echo -e "c_otp: $pkgver" > PKG-INFO
  make
}

package() {
  cd "${srcdir}"/$_pkgname/bin || exit -1
  echo "Copy ${srcdir}/$_pkgname/bin/c_otp usr/bin/"
  #make PREFIX="$pkgdir"/usr DESTDIR="$pkgdir" install
  install -Dm755 ${srcdir}/$_pkgname/bin/$_pkgname "$pkgdir/$bindir/$_pkgname"
  install -m644 -D ${srcdir}/$_pkgname/LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
