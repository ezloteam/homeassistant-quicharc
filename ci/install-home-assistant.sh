#!/bin/sh
# Install Home Assistant and the test helpers built for that release.
#
#   ci/install-home-assistant.sh [pip options] REQUIREMENT
#
# e.g. "homeassistant" (newest stable), "--pre homeassistant" (newest beta)
# or "homeassistant==2026.11.0b1". From 2026.11 the helpers are Home
# Assistant's own pytest-homeassistant (module pytest_homeassistant), one
# release per Home Assistant release: from PyPI when that version is there,
# otherwise built from core's tag. Core named it pytest-home-assistant until
# 2026.11.0b3 and pytest-homeassistant from b4; both are tried. The exact
# version pin keeps an unrelated old PyPI project of the same name (0.1.x)
# from ever matching. Earlier releases use
# pytest-homeassistant-custom-component.
#
# Exits 77 when no helpers can be installed for the release.
set -eu

pip install --upgrade "$@" pytest-timeout "ruamel.yaml>=0.18"
HA=$(python -c "import homeassistant.const as c; print(c.__version__)")
NEW=$(python -c "import homeassistant.const as c; print(int((c.MAJOR_VERSION, c.MINOR_VERSION) >= (2026, 11)))")

CORE="git+https://github.com/home-assistant/core@$HA#subdirectory=packages"
if [ "$NEW" = 1 ]; then
  if pip install "pytest-homeassistant==$HA"; then
    HARNESS="pytest-homeassistant $HA (PyPI)"
  elif pip install "pytest-home-assistant==$HA"; then
    HARNESS="pytest-home-assistant $HA (PyPI)"
  elif pip install "pytest-homeassistant @ $CORE/pytest-homeassistant"; then
    HARNESS="pytest-homeassistant (core $HA)"
  elif pip install "pytest-home-assistant @ $CORE/pytest-home-assistant"; then
    HARNESS="pytest-home-assistant (core $HA)"
  else
    exit 77
  fi
else
  # It pins an exact release; put the one asked for back over it.
  pip install pytest-homeassistant-custom-component || exit 77
  pip install "homeassistant==$HA"
  HARNESS=pytest-homeassistant-custom-component
fi
echo "Home Assistant $HA with $HARNESS"
