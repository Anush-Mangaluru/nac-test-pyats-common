# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""SD-WAN (SDWAN Manager) adapter module for NAC PyATS testing.

This module provides SD-WAN-specific authentication, test base classes, and device
resolver implementations for use with the nac-test framework. It includes support
for both SDWAN Manager API testing and SSH-based device-to-device (D2D) testing.

Classes:
    SDWANManagerAuth: SDWAN Manager authentication with session auth (JSESSIONID +
        XSRF token) and API token auth (JWT Bearer + CSRF, 20.18+).
    SDWANManagerTestBase: Base class for SDWAN Manager API tests with tracking.
    SDWANTestBase: Base class for SD-WAN SSH/D2D tests with device inventory.
    SDWANDeviceResolver: Resolves device information from the SD-WAN data model.

Example:
    For SDWAN Manager API testing:

    >>> from nac_test_pyats_common.sdwan import SDWANManagerTestBase
    >>>
    >>> class VerifyDeviceList(SDWANManagerTestBase):
    ...     async def get_items_to_verify(self):
    ...         return ['device1', 'device2']
    ...
    ...     async def verify_item(self, item):
    ...         response = await self.client.get(f"/dataservice/device/{item}")
    ...         return response.status_code == 200

    For SSH/D2D testing:

    >>> from nac_test_pyats_common.sdwan import SDWANTestBase
    >>>
    >>> class VerifyInterfaceStatus(SDWANTestBase):
    ...     @aetest.test
    ...     def verify_interfaces(self, steps, device):
    ...         # SSH-based verification
    ...         pass
"""

from .api_test_base import SDWANManagerTestBase
from .auth import SDWANManagerAuth
from .device_resolver import SDWANDeviceResolver
from .ssh_test_base import SDWANTestBase

__all__ = [
    "SDWANManagerAuth",
    "SDWANManagerTestBase",
    "SDWANTestBase",
    "SDWANDeviceResolver",
]
