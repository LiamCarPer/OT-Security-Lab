"""Normalized OT NDR telemetry producers.

Live protocol decoders that turn packets observed on the gateway into the
normalized events the generated Loki ruler rules consume (see the telemetry
contract). Each decoder is a pure function over a TCP payload so it can be unit
tested without a sniffer; the top-level ``*_dpi.py`` services own the sniffers
and the Loki/alert sinks.
"""
