if [ ! $1 ]  ; then
    echo "" 
    echo "    Usage: buildrpm.sh <path_to_spec_file>"
    echo ""
    exit 1
fi

if [ ! -f $1 ]  ; then
    echo "" 
    echo "    Error: Couldn't find spec file: $1>"
    echo ""
    exit 1
fi

curr_dir=`pwd`
script=$(dirname $0)
root=$script/..
cd $root
root=`pwd`

version=2.0.15
rpm_spec_file=$1

if [ $1 != "/*" ]; then
    rpm_spec_file=$curr_dir/$1
fi

mkdir_if_not_exits()
{
    if [ ! -d $1 ]; then
        echo "mkdir $1"
        mkdir $1
    fi
}

set -e

file_name=$(basename $rpm_spec_file)
build_name=`echo $file_name | sed 's/\.spec//'`

build=$root/build
source=WALinuxAgent-$version
rpm_top=$build/$build_name
rpm_tmp=$rpm_top/TMP
rpm_specs=$rpm_top/SPECS
rpm_src=$rpm_top/SOURCES

mkdir_if_not_exits $build
mkdir_if_not_exits $rpm_top
mkdir_if_not_exits $rpm_tmp
mkdir_if_not_exits $rpm_specs
mkdir_if_not_exits $rpm_src

#----------------------------
#create source code archive
#----------------------------
echo "rsync -a --exclude '.git' --exclude 'build' $root/ $rpm_tmp/$source"
rsync -a --exclude '.git' --exclude 'build' $root/ $rpm_tmp/$source

echo "cd $rpm_tmp"
cd $rpm_tmp

echo "tar -czf ${source}.tar.gz $source"
tar -czf ${source}.tar.gz $source

echo "cp $rpm_tmp/${source}.tar.gz $rpm_src"
cp $rpm_tmp/${source}.tar.gz $rpm_src

#----------------------------
#copy rpm spec file
#----------------------------
echo "cp $rpm_spec_file $rpm_specs"
cp $rpm_spec_file $rpm_specs

#----------------------------
#rpmbuild
#----------------------------
if [ -d $rpm_top/BUILDROOT ]; then
    rm $rpm_top/BUILDROOT/ -r
fi
echo "rpmbuild -ba --define '_topdir $rpm_top' --clean $rpm_spec_file"
rpmbuild -ba --define "_topdir $rpm_top" --define "_agentversion $version" --clean $rpm_spec_file


