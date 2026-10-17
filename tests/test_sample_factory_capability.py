from __future__ import annotations

import unittest

from packages.sample_factory.capability import capability_paths, validate_capability_closure
from packages.sample_factory.errors import CatalogError

from tests.sample_factory_fixtures import atom_specs


class CapabilityGraphTest(unittest.TestCase):
    def test_discovers_and_validates_ordered_capability_path(self) -> None:
        specs = atom_specs()
        validate_capability_closure(specs)
        paths = capability_paths(specs)
        self.assertIn(tuple(spec.atom_id for spec in specs), paths)

    def test_rejects_consumer_before_provider(self) -> None:
        carrier, loader, execution = atom_specs()
        with self.assertRaisesRegex(CatalogError, "未被前序"):
            validate_capability_closure((carrier, execution, loader))

    def test_partial_capability_contract_is_rejected(self) -> None:
        carrier, loader, execution = atom_specs()
        with self.assertRaisesRegex(CatalogError, "不完整"):
            validate_capability_closure(
                (carrier, loader.model_copy(update={"provided_capabilities": ()}), execution)
            )


if __name__ == "__main__":
    unittest.main()
