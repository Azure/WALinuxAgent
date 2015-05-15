script=$(dirname $0)
root=$script/..
cd $root
root=`pwd`

version=WALinuxAgent-2.0.13

mkdir -p ~/rpmbuild/TMP
mkdir -p ~/rpmbuild/SPECS
mkdir -p ~/rpmbuild/SOURCES


echo "rsync -a --exclude '.*' $root/ ~/rpmbuild/TMP/$version"
rsync -a --exclude '.*' $root/ ~/rpmbuild/TMP/$version

echo "cd ~/rpmbuild/TMP"
cd ~/rpmbuild/TMP

echo "tar -czf ${version}.tar.gz $version"
tar -czf ${version}.tar.gz $version

echo "cp $root/rpm/walinuxagent.spec ~/rpmbuild/SPECS"
cp $root/rpm/walinuxagent.spec ~/rpmbuild/SPECS

echo "cp ~/rpmbuild/TMP/${version}.tar.gz ~/rpmbuild/SOURCES"
cp ~/rpmbuild/TMP/${version}.tar.gz ~/rpmbuild/SOURCES

echo "rpmbuild -ba ~/rpmbuild/SPECS/walinuxagent.spec"
rpmbuild -ba ~/rpmbuild/SPECS/walinuxagent.spec


