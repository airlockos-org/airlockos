"""Construct real upstream Qubes objects without a live hypervisor or daemon.

Rust owns the scenario and assertions; this fixture exposes Qubes' Python API.
"""

import asyncio
import importlib.util
import json
import pathlib
import sys
import tempfile

import qubes
import qubes.config
import qubes.ext
import qubes.vm.appvm

request = json.load(sys.stdin)
spec = importlib.util.spec_from_file_location("airlock_qubes", request["module"])
module = importlib.util.module_from_spec(spec)
sys.modules["airlock_qubes"] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as directory, asyncio.Runner() as runner:
    root = pathlib.Path(directory)
    qubes.ext.get_extensions = set
    qubes.config.qubes_base_dir = str(root)
    qubes.config.defaults["pool_configs"] = {
        "varlibqubes": {"name": "varlibqubes", "driver": "file", "dir_path": str(root)},
        "linux-kernel": {
            "name": "linux-kernel", "driver": "linux-kernel",
            "dir_path": str(root / "kernels"),
        },
    }
    app = qubes.Qubes.create_empty_store(str(root / "qubes.xml"), offline_mode=True)
    try:
        app.events_enabled = False
        app.default_kernel = ""
        app.default_template = None
        vm = app.add_new_vm(module.HermitVM, name="sys-clipboard", label="black")
        vm.events_enabled = False
        for name, value in request["domain"]["prefs"].items():
            setattr(vm, name, value)
        vm.netvm = None
        for name, value in request["domain"]["features"].items():
            vm.features[name] = value
        vm.features["airlock-hermit-artifact"] = json.dumps(request["domain"]["backend"]["artifact"])
        vm.features["airlock-hermit-generation"] = "/test-generation"
        vm._airlock_hermit_nonce = request["nonce"]
        reply = {"class": type(vm).__name__, "volumes": list(vm.volumes)}
        try:
            reply["xml"] = vm.create_config_file()
        except qubes.exc.QubesException as error:
            reply["error"] = str(error)
        print(json.dumps(reply))
    finally:
        app.close()
