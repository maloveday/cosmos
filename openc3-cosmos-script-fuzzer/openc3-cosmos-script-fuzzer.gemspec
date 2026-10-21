# encoding: ascii-8bit
# SPDX-License-Identifier: MIT

spec = Gem::Specification.new do |s|
  s.name = 'openc3-cosmos-script-fuzzer'
  s.summary = 'Headless coverage-guided fuzzer for OpenC3 COSMOS Script Runner procedures'
  s.description = <<-EOF
    Executes Script Runner procedures against a Redis-backed telemetry simulation,
    fuzzes telemetry values, command responses and operator prompts, tracks line and
    branch coverage with Coverage.py, interrupts stale executions, and produces
    Robot Framework-style HTML reports.
  EOF
  s.license = 'MIT'
  s.authors = ['OpenC3 Script Fuzzer Contributors']
  s.email = ['']
  s.homepage = 'https://github.com/OpenC3/cosmos'
  s.platform = Gem::Platform::RUBY
  s.required_ruby_version = '>= 3.0'

  s.metadata = {
    'openc3_store_title' => 'Script Fuzzer',
    'openc3_store_description' => 'Coverage-guided fuzzing and validation of Script Runner procedures with Robot Framework-style reports.',
    'openc3_store_keywords' => 'testing,fuzzing,coverage,script runner,python,robot framework',
    'openc3_store_access_type' => 'public',
    'openc3_cosmos_minimum_version' => '6.0.0',
    'source_code_uri' => 'https://github.com/OpenC3/cosmos',
  }

  if ENV['VERSION']
    s.version = ENV['VERSION'].dup
  else
    time = Time.now.strftime("%Y%m%d%H%M%S")
    s.version = '0.0.0' + ".#{time}"
  end
  s.files = Dir.glob("{targets,lib,procedures,tools,microservices,examples}/**/*") +
            %w(Rakefile README.md LICENSE.md plugin.txt requirements.txt)
end
