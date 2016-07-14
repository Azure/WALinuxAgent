from distutils import version
import re

class FlexibleVersion(version.Version):
    """
    A more flexible implementation of distutils.version.StrictVersion

    The implementation allows to specify:
    - an arbitrary number of version numbers:
        not only '1.2.3' , but also '1.2.3.4.5'
    - the separator between version numbers:
        '1-2-3' is allowed when '-' is specified as separator
    - a flexible pre-release separator:
        '1.2.3.alpha1', '1.2.3-alpha1', and '1.2.3alpha1' are considered equivalent
    - an arbitrary ordering of pre-release tags:
        1.1alpha3 < 1.1beta2 < 1.1rc1 < 1.1
        when ["alpha", "beta", "rc"] is specified as pre-release tag list

    Inspiration from this discussion at StackOverflow:
        http://stackoverflow.com/questions/12255554/sort-versions-in-python
    """

    def __init__(self, vstring=None, sep='.', prerel_tags=('alpha', 'beta', 'rc')):
        version.Version.__init__(self) 

        if sep is None:
            sep = '.'
        if prerel_tags is None:
            prerel_tags = ()

        self.sep = sep
        self.prerel_sep = ''
        self.prerel_tags = tuple(prerel_tags) if prerel_tags is not None else ()

        self._compile_pattern()

        self.prerelease = None
        self.version = ()
        if vstring:
            self._parse(vstring)
        return

    _nn_version = 'version'
    _nn_prerel_sep = 'prerel_sep'
    _nn_prerel_tag = 'tag'
    _nn_prerel_num = 'tag_num'

    _re_prerel_sep = r'(?P<{pn}>{sep})?'.format(
        pn=_nn_prerel_sep,
        sep='|'.join(map(re.escape, ('.', '-'))))

    @property
    def major(self):
        return self.version[0] if len(self.version) > 0 else 0

    @property
    def minor(self):
        return self.version[1] if len(self.version) > 1 else 0

    @property
    def patch(self):
        return self.version[2] if len(self.version) > 2 else 0

    def _parse(self, vstring):
        m = self.version_re.match(vstring)
        if not m:
            raise ValueError("Invalid version number '{0}'".format(vstring))

        self.prerelease = None
        self.version = ()

        self.prerel_sep = m.group(self._nn_prerel_sep)
        tag = m.group(self._nn_prerel_tag)
        tag_num = m.group(self._nn_prerel_num)

        if tag is not None and tag_num is not None:
            self.prerelease = (tag, int(tag_num) if len(tag_num) else None)

        self.version = tuple(map(int, self.sep_re.split(m.group(self._nn_version))))
        return

    def __add__(self, increment):
        version = list(self.version)
        version[-1] += increment
        vstring = self._assemble(version, self.sep, self.prerel_sep, self.prerelease)
        return FlexibleVersion(vstring=vstring, sep=self.sep, prerel_tags=self.prerel_tags)

    def __sub__(self, decrement):
        version = list(self.version)
        if version[-1] <= 0:
            raise ArithmeticError("Cannot decrement final numeric component of {0} below zero" \
                .format(self))
        version[-1] -= decrement
        vstring = self._assemble(version, self.sep, self.prerel_sep, self.prerelease)
        return FlexibleVersion(vstring=vstring, sep=self.sep, prerel_tags=self.prerel_tags)

    def __repr__(self):
        return "{cls} ('{vstring}', '{sep}', {prerel_tags})"\
            .format(
                cls=self.__class__.__name__,
                vstring=str(self),
                sep=self.sep,
                prerel_tags=self.prerel_tags)

    def __str__(self):
        return self._assemble(self.version, self.sep, self.prerel_sep, self.prerelease)

    def __ge__(self, that):
        return not self.__lt__(that)

    def __gt__(self, that):
        return (not self.__lt__(that)) and (not self.__eq__(that))

    def __le__(self, that):
        return (self.__lt__(that)) or (self.__eq__(that))

    def __lt__(self, that):
        this_version, that_version = self._ensure_compatible(that)

        if this_version != that_version \
           or self.prerelease is None and that.prerelease is None:
            return this_version < that_version

        if self.prerelease is not None and that.prerelease is None:
            return True
        if self.prerelease is None and that.prerelease is not None:
            return False

        this_index = self.prerel_tags_set[self.prerelease[0]]
        that_index = self.prerel_tags_set[that.prerelease[0]]
        if this_index == that_index:
            return self.prerelease[1] < that.prerelease[1]

        return this_index < that_index

    def __ne__(self, that):
        return not self.__eq__(that)

    def __eq__(self, that):
        this_version, that_version = self._ensure_compatible(that)

        if this_version != that_version:
            return False

        if self.prerelease != that.prerelease:
            return False

        return True

    def _assemble(self, version, sep, prerel_sep, prerelease):
        s = sep.join(map(str, version))
        if prerelease is not None:
            if prerel_sep is not None:
                s += prerel_sep
            s += prerelease[0]
            if prerelease[1] is not None:
                s += str(prerelease[1])
        return s

    def _compile_pattern(self):
        sep, self.sep_re = self._compile_separator(self.sep)

        if self.prerel_tags:
            tags = '|'.join(re.escape(tag) for tag in self.prerel_tags)
            self.prerel_tags_set = dict(zip(self.prerel_tags, range(len(self.prerel_tags))))
            release_re = '(?:{prerel_sep}(?P<{tn}>{tags})(?P<{nn}>\d*))?'.format(
                        prerel_sep=self._re_prerel_sep,
                        tags=tags,
                        tn=self._nn_prerel_tag,
                        nn=self._nn_prerel_num)
        else:
            release_re = ''

        version_re = r'^(?P<{vn}>\d+(?:(?:{sep}\d+)*)?){rel}$'.format(
            vn=self._nn_version,
            sep=sep,
            rel=release_re)
        self.version_re = re.compile(version_re)
        return

    def _compile_separator(self, sep):
        if sep is None:
            return '', re.compile('')
        return re.escape(sep), re.compile(re.escape(sep))

    def _ensure_compatible(self, that):
        """
        Ensures the instances have the same structure and, if so, returns length compatible
        version lists (so that x.y.0.0 is equivalent to x.y).
        """
        if self.prerel_tags != that.prerel_tags or self.sep != that.sep:
            raise ValueError("Unable to compare: versions have different structures")

        this_version = list(self.version[:])
        that_version = list(that.version[:])
        while len(this_version) < len(that_version): this_version.append(0)
        while len(that_version) < len(this_version): that_version.append(0)

        return this_version, that_version
