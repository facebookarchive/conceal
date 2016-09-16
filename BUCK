android_library(
  name = 'conceal_android',
  srcs = glob(['java/com/facebook/android/**/*.java']),
  visibility = [
    'PUBLIC',
  ],
  deps = [
    ':libconceal',
  ],
)

java_library(
  name = 'libconceal',
  srcs = glob([
    'java/com/facebook/crypto/**/*.java',
    'java/com/facebook/proguard/**/*.java',
  ]),
  proguard_config = 'proguard_annotations.pro',
  visibility = [ 
    'PUBLIC',
  ],
  deps = [
    '//native/crypto:crypto',
  ]
)

robolectric_test(
  name = 'android_tests',
  srcs = glob(['javatests/com/facebook/android/**/*Test.java']),
  deps = [
    ':libconceal',
    ':conceal_android',
    '//third-party/junit:junit',
    '//third-party/junit:hamcrest',
    '//third-party/guava:guava',
    '//third-party/robolectric2:robolectric2',
  ],
)

java_test(
  name = 'conceal_tests',
  srcs = glob(['javatests/com/facebook/crypto/**/*Test.java']),
  deps = [
    ':libconceal',
    ':crypto-test-helper',
    '//third-party/junit:junit',
    '//third-party/junit:hamcrest',
    '//third-party/guava:guava',
  ],
)

java_library(
  name = 'crypto-test-helper',
  srcs = glob(
    ['javatests/com/facebook/crypto/**/*.java'],
    excludes = glob(['javatests/com/facebook/crypto/**/*Test.java'])
  ),
  deps = [
    ':libconceal',
    '//third-party/junit:junit',
    '//third-party/junit:hamcrest',
  ],
)

project_config(
  src_target = ':conceal_android',
  src_roots = [ 'java' ],
)
