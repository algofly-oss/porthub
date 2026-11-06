import copy
import contextlib
import io
from types import SimpleNamespace
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('buildplan', Path(__file__).with_name('component-build-plan.py'))
buildplan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(buildplan)
TARGET = 'x86_64-unknown-linux-gnu'


class BuildPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='porthub build inputs ')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.write('Cargo.toml', '''[workspace]
members = ["core", "tool", "support"]
[workspace.package]
version = "1.11.0"
edition = "2021"
publish = false
[workspace.dependencies]
dep-a = "1"
''')
        self.write('rust-toolchain.toml', '[toolchain]\nchannel="1.99.1"\nprofile="minimal"\ncomponents=["clippy"]\n')
        self.write('deploy/components.toml', '''schema_version=1
[tools.core]
package="core"
manifest="core/Cargo.toml"
binary="core"
default_features=true
features=[]
extra_inputs=[]
profile="release"
recipe_version=1
[tools.tool]
package="tool"
manifest="tool/Cargo.toml"
binary="tool"
default_features=true
features=[]
extra_inputs=[]
profile="release"
recipe_version=1
''')
        self.write('core/Cargo.toml', '[package]\nname="core"\nversion.workspace=true\nedition.workspace=true\n[dependencies]\nsupport={path="../support"}\n')
        self.write('tool/Cargo.toml', '[package]\nname="tool"\nversion="0.1.0"\nedition.workspace=true\npublish.workspace=true\n[dependencies]\nsupport={path="../support"}\n')
        self.write('support/Cargo.toml', '[package]\nname="support"\nversion="0.1.0"\nedition.workspace=true\n[dependencies]\ndep-a.workspace=true\n')
        self.write('core/src/main.rs', 'fn main() {}\n')
        self.write('tool/src/main.rs', 'fn main() {}\n')
        self.write('support/src/lib.rs', 'pub fn value()->u8 {1}\n')
        self.packages = [
            {'name': 'core', 'version': '1.11.0', 'dependencies': ['support']},
            {'name': 'tool', 'version': '0.1.0', 'dependencies': ['support']},
            {'name': 'support', 'version': '0.1.0', 'dependencies': ['dep-a']},
            {'name': 'dep-a', 'version': '1.0.0', 'source': 'registry+https://github.com/rust-lang/crates.io-index', 'checksum': 'a' * 64},
        ]
        self.lock()
        self.binary = self.root / 'target/tool'
        self.write('target/tool', 'independent executable fixture')
        self.dep = self.root / 'target/tool.d'
        self.deps('tool')
        self.receipt = self.record('tool')

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def lock(self):
        rows = ['version = 4\n']
        for package in self.packages:
            rows.append('[[package]]\n' + '\n'.join(key + ' = ' + json.dumps(value) for key, value in package.items()))
        self.write('Cargo.lock', '\n'.join(rows))

    def deps(self, tool):
        escape = lambda path: str(path).replace('\\', '\\\\').replace(' ', '\\ ')
        paths = [self.root / tool / 'src/main.rs', self.root / 'support/src/lib.rs']
        self.dep.write_text(escape(self.binary) + ': ' + ' '.join(map(escape, paths)) + '\n')
        # No assumptions about Windows timestamp granularity in this fixture.
        stamp = self.binary.stat().st_mtime_ns + 1_000_000_000
        os.utime(self.dep, ns=(stamp, stamp))

    def record(self, tool):
        version = '1.11.0' if tool == 'core' else '0.1.0'
        tree = (f'0{tool} v{version} ({self.root / tool})|\n'
                f'1support v0.1.0 ({self.root / "support"})|\n'
                '2dep-a v1.0.0|default,std\n')
        return buildplan.record(self.root, tool, TARGET, self.binary, self.dep, 'a' * 40, tree=tree)

    def choose(self):
        return buildplan.plan(self.root, 'tool', TARGET, self.receipt)

    def test_terminal_bundle_is_a_hashed_derived_input_not_untracked_source(self):
        recipes=self.root/'deploy/components.toml'
        text=recipes.read_text().replace('package="tool"','package="porthub-terminal-cli"')
        head,tool=text.split('[tools.tool]',1)
        tool=tool.replace('extra_inputs=[]','extra_inputs=["scripts/build-terminal-helper.py","vendor/terminal/sources.json"]')
        recipes.write_text(head+'[tools.tool]'+tool)
        manifest=self.root/'tool/Cargo.toml'
        manifest.write_text(manifest.read_text().replace('name="tool"','name="porthub-terminal-cli"'))
        self.packages[1]['name']='porthub-terminal-cli';self.lock()
        self.write('scripts/build-terminal-helper.py','pinned producer')
        self.write('vendor/terminal/sources.json','pinned source identities')
        self.write('.cache/runtime/bundle.tar.gz','derived bundle bytes')
        bundle=self.root/'.cache/runtime/bundle.tar.gz'
        self.deps('tool')
        escaped=str(bundle).replace('\\','\\\\').replace(' ','\\ ')
        text=self.dep.read_text().rstrip('\n')+' '+escaped+'\n'
        self.dep.write_text(text)
        tree=(f'0porthub-terminal-cli v0.1.0 ({self.root/"tool"})|\n'
              f'1support v0.1.0 ({self.root/"support"})|\n2dep-a v1.0.0|default,std\n')
        with mock.patch.dict(os.environ,{'PORTHUB_TERMINAL_BUNDLE':str(bundle)}):
            receipt=buildplan.record(self.root,'tool',TARGET,self.binary,self.dep,'a'*40,tree=tree)
            self.assertNotIn('.cache/runtime/bundle.tar.gz',[row[0] for row in receipt['build']['inputs']])
            self.assertEqual(receipt['build']['derived_inputs']['terminal_bundle']['sha256'],buildplan.file_digest(bundle))
            self.assertEqual(buildplan.plan(self.root,'tool',TARGET,receipt)['action'],'reuse')
            bundle.write_bytes(b'changed derived bundle')
            self.assertEqual(buildplan.plan(self.root,'tool',TARGET,receipt)['version'],'0.1.1')

    def shipping_recipe(self, flags='-C target-feature=+crt-static'):
        self.write('deploy/component-platforms.toml', 'schema_version=1\n[defaults]\nCARGO_INCREMENTAL="0"\n[targets."'+TARGET+'"]\nrustflags='+json.dumps(flags)+'\n')

    def test_declared_target_environment_proves_reuse_from_another_host(self):
        self.shipping_recipe()
        with mock.patch.dict(os.environ,{'RUSTFLAGS':'-C target-feature=+crt-static','CARGO_INCREMENTAL':'0'}):
            receipt=self.record('tool')
        with mock.patch.dict(os.environ,{'RUSTFLAGS':'','CARGO_INCREMENTAL':''}):
            self.assertEqual(buildplan.plan(self.root,'tool',TARGET,receipt)['action'],'build')
            environment=buildplan.shipping_environment(self.root,TARGET)
            self.assertEqual(buildplan.plan(self.root,'tool',TARGET,receipt,environment=environment)['action'],'reuse')
            self.shipping_recipe('-C opt-level=2')
            changed=buildplan.shipping_environment(self.root,TARGET)
            self.assertEqual(buildplan.plan(self.root,'tool',TARGET,receipt,environment=changed)['action'],'build')

    def test_unexpected_shipping_flags_fail_before_compilation(self):
        self.shipping_recipe()
        with mock.patch.dict(os.environ,{'RUSTFLAGS':'-C opt-level=1','CARGO_INCREMENTAL':'0'}), mock.patch.object(buildplan,'require_clean_source'), mock.patch.object(buildplan.subprocess,'run',side_effect=AssertionError('Must reject before Cargo')):
            with self.assertRaisesRegex(ValueError,'Shipping compiler environment differs'):
                buildplan.build_and_record(self.root,'tool',TARGET,'a'*40)

    def test_terminal_compiler_cache_location_is_portable(self):
        cache=self.root/'private compiler cache'
        key='CC_'+TARGET.replace('-','_')
        with mock.patch.dict(os.environ,{'PORTHUB_TERMINAL_HELPER_CACHE_ROOT':str(cache)}):
            normalized=buildplan.normalize_environment(self.root,{key:str(cache/'target/id/musl-runtime/bin/musl-gcc'),'RUSTFLAGS':''})
        self.assertEqual(normalized,{key:'{terminal-cache}/target/id/musl-runtime/bin/musl-gcc'})

    @unittest.skipIf(os.name == 'nt', 'Directory symlink privilege is not assumed on Windows')
    def test_terminal_compiler_cache_alias_is_portable(self):
        cache=self.root/'private compiler cache'
        cache.mkdir()
        alias=self.root/'cache alias'
        alias.symlink_to(cache, target_is_directory=True)
        key='CC_'+TARGET.replace('-','_')
        with mock.patch.dict(os.environ,{'PORTHUB_TERMINAL_HELPER_CACHE_ROOT':str(cache)}):
            normalized=buildplan.normalize_environment(self.root,{key:str(alias/'target/id/musl-runtime/bin/musl-gcc')})
        self.assertEqual(normalized,{key:'{terminal-cache}/target/id/musl-runtime/bin/musl-gcc'})

    def test_declared_cross_compiler_points_at_actual_terminal_builder_cache(self):
        repository=Path(__file__).resolve().parents[1]
        producer=repository/'scripts/build-terminal-helper.py'
        (self.root/'scripts').mkdir(exist_ok=True)
        (self.root/'scripts/build-terminal-helper.py').write_bytes(producer.read_bytes())
        (self.root/'vendor/terminal').mkdir(parents=True,exist_ok=True)
        (self.root/'vendor/terminal/sources.json').write_bytes((repository/'vendor/terminal/sources.json').read_bytes())
        self.write('deploy/component-platforms.toml','schema_version=1\n[defaults]\nCARGO_INCREMENTAL="0"\n[targets."'+TARGET+'"]\nterminal_compiler=true\nsource_cc="cross-gcc"\nar="cross-ar"\n')
        environment=buildplan.shipping_environment(self.root,TARGET)
        compiler=environment['CC_'+TARGET.replace('-','_')]
        identity=compiler.split('/')[2]
        cache=self.root/'compiler-cache'
        bundle=cache/TARGET/identity/'bundle.tar.gz'
        bundle.parent.mkdir(parents=True);bundle.write_bytes(b'cached fixture')
        spec=importlib.util.spec_from_file_location('terminal_producer',producer)
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        with mock.patch.object(builder,'ROOT',self.root), mock.patch.dict(os.environ,{'PORTHUB_TERMINAL_HELPER_CACHE_ROOT':str(cache)}), mock.patch.object(builder,'download_source',side_effect=AssertionError('Expected exact cache hit')), contextlib.redirect_stdout(io.StringIO()) as stdout:
            builder.build(SimpleNamespace(target=TARGET,cc='cross-gcc',ar='cross-ar',jobs=1))
        self.assertEqual(Path(stdout.getvalue().strip()),bundle)

    def test_build_script_modules_are_inputs_even_when_absent_from_binary_depfile(self):
        self.write('tool/build.rs','mod build_support; fn main() {}\n')
        self.write('tool/build_support.rs','pub fn target_check() {}\n')
        script_dep=self.root/'target/build-script.d'
        escape=lambda path:str(path).replace('\\','\\\\').replace(' ','\\ ')
        script_dep.write_text('build-script: '+escape(self.root/'tool/build.rs')+' '+escape(self.root/'tool/build_support.rs')+'\n')
        tree=(f'0tool v0.1.0 ({self.root/"tool"})|\n'
              f'1support v0.1.0 ({self.root/"support"})|\n2dep-a v1.0.0|default,std\n')
        receipt=buildplan.record(self.root,'tool',TARGET,self.binary,self.dep,'a'*40,tree=tree,script_dep_infos=[script_dep])
        self.assertIn('tool/build_support.rs',[row[0] for row in receipt['build']['inputs']])
        self.assertEqual(buildplan.plan(self.root,'tool',TARGET,receipt)['action'],'reuse')
        self.write('tool/build_support.rs','pub fn changed_target_check() {}\n')
        self.assertEqual(buildplan.plan(self.root,'tool',TARGET,receipt)['action'],'build')

    def test_independent_core_reuses_after_server_workspace_version_bump(self):
        path = self.root/'core/Cargo.toml'
        path.write_text(path.read_text().replace('version.workspace=true', 'version="1.11.0"'))
        self.deps('core')
        receipt = self.record('core')
        workspace = self.root/'Cargo.toml'
        workspace.write_text(workspace.read_text().replace('version = "1.11.0"', 'version = "1.12.0"'))
        choice = buildplan.plan(self.root, 'core', TARGET, receipt)
        self.assertEqual(choice['action'], 'reuse')
        self.assertEqual(choice['version'], '1.11.0')

    def test_agent_only_edits_and_unrelated_lock_changes_reuse_helper(self):
        self.write('core/src/main.rs', 'fn main() {println!("new core behavior");}\n')
        self.packages.append({'name': 'unrelated', 'version': '9.0.0', 'source': 'registry+https://github.com/rust-lang/crates.io-index', 'checksum': 'b' * 64})
        self.lock()
        choice = self.choose()
        self.assertEqual(choice['action'], 'reuse')
        self.assertTrue(choice['requires_artifact_verification'])
        buildplan.verify_reuse(self.receipt, self.binary)

    def test_selection_reuses_without_running_cargo_or_fetching_registry_manifests(self):
        with mock.patch.object(buildplan.subprocess, 'run', side_effect=AssertionError('Selection must stay offline')):
            self.assertEqual(self.choose()['action'], 'reuse')

    def test_transitive_source_change_advances_only_helper_version(self):
        self.write('support/src/lib.rs', 'pub fn value()->u8 {2}\n')
        choice = self.choose()
        self.assertEqual(choice['action'], 'build')
        self.assertEqual(choice['version'], '0.1.1')

    def test_source_checksum_and_selected_edge_changes_force_rebuild(self):
        self.packages[-1]['checksum'] = 'c' * 64
        self.lock()
        self.assertEqual(self.choose()['action'], 'build')
        self.packages[-1]['checksum'] = 'a' * 64
        self.packages.append({**self.packages[-1], 'version': '1.0.1'})
        self.packages[2]['dependencies'] = ['dep-a 1.0.1']
        self.lock()
        self.assertEqual(self.choose()['action'], 'build', 'Old version still in the lock must not hide a new selected dependency')

    def test_workspace_version_bump_rebuilds_core_without_rebuilding_fixed_helpers(self):
        self.deps('core')
        core = self.record('core')
        self.write('Cargo.toml', (self.root / 'Cargo.toml').read_text().replace('1.11.0', '1.11.1'))
        self.packages[0]['version'] = '1.11.1'
        self.lock()
        self.assertEqual(self.choose()['action'], 'reuse')
        choice = buildplan.plan(self.root, 'core', TARGET, core)
        self.assertEqual((choice['action'], choice['version']), ('build', '1.11.1'))

    def test_new_recipe_entry_does_not_rebuild_other_tools(self):
        self.write('deploy/components.toml', (self.root / 'deploy/components.toml').read_text() + '\n[tools.stats]\npackage="stats"\n')
        self.assertEqual(self.choose()['action'], 'reuse')

    def test_feature_toolchain_and_target_changes_invalidate_reuse(self):
        recipe = self.root / 'deploy/components.toml'
        original = recipe.read_text()
        self.write('deploy/components.toml', original.replace('[tools.tool]\n', '[tools.tool]\n').replace('profile="release"', 'profile="agent-dev"'))
        self.assertEqual(self.choose()['action'], 'build')
        self.write('deploy/components.toml', original)
        self.write('rust-toolchain.toml', '[toolchain]\nchannel="1.99.2"\n')
        self.assertEqual(self.choose()['action'], 'build')
        choice = buildplan.plan(self.root, 'tool', 'aarch64-pc-windows-msvc', self.receipt)
        self.assertEqual(choice['action'], 'build')

    def test_directory_inputs_detect_added_files_and_deleted_inputs_force_build(self):
        recipe = self.root / 'deploy/components.toml'
        self.write('templates/first', 'one')
        self.write('deploy/components.toml', recipe.read_text().replace('extra_inputs=[]', 'extra_inputs=["templates"]'))
        self.receipt = self.record('tool')
        self.write('templates/second', 'two')
        self.assertEqual(self.choose()['action'], 'build')
        (self.root / 'support/src/lib.rs').unlink()
        self.assertEqual(self.choose()['action'], 'build')

    def test_release_profile_and_relevant_compiler_flags_are_inputs(self):
        self.write('Cargo.toml', (self.root / 'Cargo.toml').read_text() + '\n[profile.release]\nlto="thin"\n')
        self.receipt = self.record('tool')
        self.write('Cargo.toml', (self.root / 'Cargo.toml').read_text() + '\n[profile.release.package.core]\nopt-level=1\n')
        self.assertEqual(self.choose()['action'], 'reuse', 'A core-only profile override must not rebuild helpers')
        self.write('Cargo.toml', (self.root / 'Cargo.toml').read_text().replace('lto="thin"', 'lto=false'))
        self.assertEqual(self.choose()['action'], 'build')
        original = os.environ.get('RUSTFLAGS')
        try:
            self.receipt = self.record('tool')
            os.environ['RUSTFLAGS'] = '-C target-cpu=generic'
            self.assertEqual(self.choose()['action'], 'build')
        finally:
            if original is None: os.environ.pop('RUSTFLAGS', None)
            else: os.environ['RUSTFLAGS'] = original

    def test_immutable_source_check_rejects_wrong_revision_and_dirty_checkout(self):
        def git(*args):
            return subprocess.run(['git', *args], cwd=self.root, capture_output=True, text=True, check=True).stdout.strip()
        git('init', '--quiet')
        git('add', '.')
        git('-c', 'user.name=Build Fixture', '-c', 'user.email=build-fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Fixture')
        revision = git('rev-parse', 'HEAD')
        buildplan.require_clean_source(self.root, revision)
        with self.assertRaisesRegex(ValueError, 'immutable revision'):
            buildplan.require_clean_source(self.root, 'b' * 40)
        self.write('tool/src/main.rs', 'fn main() {println!("uncommitted");}')
        with self.assertRaisesRegex(ValueError, 'uncommitted'):
            buildplan.require_clean_source(self.root, revision)

    def test_workspace_resolver_and_inherited_lints_are_relevant_inputs(self):
        original = (self.root / 'Cargo.toml').read_text()
        self.write('Cargo.toml', original.replace('[workspace]\n', '[workspace]\nresolver="2"\n'))
        self.receipt = self.record('tool')
        self.write('Cargo.toml', (self.root / 'Cargo.toml').read_text().replace('resolver="2"', 'resolver="1"'))
        self.assertEqual(self.choose()['action'], 'build')
        self.write('tool/Cargo.toml', (self.root / 'tool/Cargo.toml').read_text() + '\n[lints]\nworkspace=true\n')
        self.write('Cargo.toml', original + '\n[workspace.lints.rust]\nunsafe_code="warn"\n')
        self.receipt = self.record('tool')
        self.write('Cargo.toml', (self.root / 'Cargo.toml').read_text().replace('unsafe_code="warn"', 'unsafe_code="deny"'))
        self.assertEqual(self.choose()['action'], 'build')

    def test_manifest_used_as_rust_input_is_hashed_as_bytes_as_well_as_effective_configuration(self):
        self.dep.write_text(self.dep.read_text().rstrip() + ' ' + str(self.root / 'tool/Cargo.toml').replace(' ', '\\ ') + '\n')
        self.receipt = self.record('tool')
        self.write('tool/Cargo.toml', (self.root / 'tool/Cargo.toml').read_text() + '\n[dev-dependencies]\nunused="4"\n')
        self.assertEqual(self.choose()['action'], 'build', 'An include_str of Cargo.toml consumes raw manifest bytes too')

    @unittest.skipUnless(os.name == 'nt', 'NTFS junction check requires native Windows')
    def test_windows_source_junctions_are_rejected(self):
        junction = self.root / 'junction'
        subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(junction), str(self.root / 'support')], capture_output=True, check=True)
        with self.assertRaisesRegex(ValueError, 'reparse'):
            buildplan.relative(self.root, junction / 'src/lib.rs')

    def test_reuse_rejects_corrupt_binary_and_receipt(self):
        self.binary.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'binary'):
            buildplan.verify_reuse(self.receipt, self.binary)
        altered = copy.deepcopy(self.receipt)
        altered['source_revision'] = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'integrity'):
            buildplan.validate_receipt(altered)

    def test_private_or_escaping_source_paths_are_rejected(self):
        for path in ['../outside', '.env', '.cargo/credentials.toml']:
            with self.assertRaises(ValueError):
                buildplan.relative(self.root, path)
        if os.name != 'nt':
            (self.root / 'link').symlink_to(self.root / 'support/src/lib.rs')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                buildplan.relative(self.root, 'link')

    @unittest.skipIf(os.name == 'nt', 'Windows short temp aliases are exercised by every fixture')
    def test_alias_above_checkout_is_allowed_but_source_symlinks_are_not(self):
        alias = self.root.parent / (self.root.name + '-parent-alias')
        alias.symlink_to(self.root.parent, target_is_directory=True)
        self.addCleanup(alias.unlink)
        checkout = alias / self.root.name
        self.assertEqual(buildplan.relative(checkout, checkout / 'support/src/lib.rs'), 'support/src/lib.rs')
        self.assertEqual(buildplan.plan(checkout, 'tool', TARGET, self.receipt)['action'], 'reuse')

    def test_changed_core_requires_an_unconsumed_version(self):
        self.deps('core')
        previous = self.record('core')
        self.write('core/src/main.rs', 'fn main() {println!("different contents");}')
        with self.assertRaisesRegex(ValueError, 'new release version'):
            buildplan.plan(self.root, 'core', TARGET, previous)

    def test_depfile_parser_handles_spaces_continuations_and_windows_drives(self):
        text = 'C\\:/work\\ space/tool.exe: C\\:/work\\ space/src/main.rs \\\n C\\:/work\\ space/src/other.rs\n\nC\\:/work\\ space/src/main.rs:\n'
        self.assertEqual(buildplan.dep_paths(text), ['C:/work space/src/main.rs', 'C:/work space/src/other.rs'])


if __name__ == '__main__':
    unittest.main()
