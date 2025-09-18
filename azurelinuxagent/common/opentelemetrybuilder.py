# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and openssl_bin 1.0+
#

from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

def initialize_tracer(service_name="AzureLinuxAgentService"):
    """
    Initializes the OpenTelemetry tracer and tracer provider with OTLP gRPC exporter.

    Args:
        service_name (str): Name of the service to be used in the resource.

    Returns:
        tracer: An OpenTelemetry tracer instance.
    """
    # Create a resource with the service name
    resource = Resource(attributes={
        SERVICE_NAME: service_name
    })

    # Create a tracer provider with the resource
    tracer_provider = TracerProvider(resource=resource)

    # Create a console span exporter
    exporter = ConsoleSpanExporter()

    # Create a batch span processor and add the exporter to it
    span_processor = BatchSpanProcessor(exporter)
    tracer_provider.add_span_processor(span_processor)

    # Set the global tracer provider
    trace.set_tracer_provider(tracer_provider)

    # Return a tracer instance
    tracer = trace.get_tracer(__name__)

    return tracer
