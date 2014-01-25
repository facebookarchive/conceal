android_library(
  name = 'crypto',
  srcs = glob(['java/**/*.java']),
  proguard_config = 'proguard_annotations.pro',
  visibility = [ 
    'PUBLIC',
  ],
  deps = [
    '//native/crypto:crypto',
  ]
)

project_config(
  src_target = ':crypto',
  src_roots = [ 'java' ],
)
