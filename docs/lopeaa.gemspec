# coding: utf-8

Gem::Specification.new do |spec|
  spec.name          = "Lopeaa"
  spec.version       = "0.3.3"
  spec.authors       = ["A. López"]
  spec.email         = ["lopeaa@gmail.com"]

  spec.summary       = %q{documentation pages.}
  spec.homepage      = "https://github.com/lopeaa/"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").select { |f| f.match(%r{^(assets|bin|_layouts|_includes|lib|Rakefile|_sass|LICENSE|README)}i) }
  spec.executables   << 'lopeaa'

  spec.add_development_dependency "bundler", "~> 2.2.32"
  spec.add_runtime_dependency "jekyll", ">= 3.8.5"
  spec.add_runtime_dependency "jekyll-seo-tag", "~> 2.0"
  spec.add_runtime_dependency "rake", ">= 12.3.1", "< 13.1.0"

end
