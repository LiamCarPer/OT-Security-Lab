"""OT Lab Caldera plugin.

The plugin only contributes data (abilities and an adversary profile). Caldera
loads those from ``data/`` when the plugin is enabled in the generated config.
"""

name = "ot-lab"
description = "OT adversary-emulation abilities for the water-treatment lab"
address = None


async def enable(services):
    """No runtime hooks are needed; abilities and adversaries are data-driven."""
    return None
