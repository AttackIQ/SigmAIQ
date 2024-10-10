import sigmaiq.sigmaiq_backend_factory as backend_factory
import sigmaiq.sigmaiq_pipeline_factory as pipeline_factory

def generate_backends_table():
    backends = backend_factory.AVAILABLE_BACKENDS
    associated_pipelines = backend_factory.SigmAIQBackend.display_all_associated_pipelines()
    table = "| Backend Option | Description | Associated Pipelines | Default Pipeline |\n|-----------------|-------------|----------------------|-------------------|\n"
    for backend, description in backends.items():
        pipelines = associated_pipelines.get(backend, {})
        pipeline_list = "<br>".join(pipelines.keys())
        default_pipeline = next(iter(pipelines.keys())) if pipelines else "N/A"
        table += f"| {backend} | {description} | {pipeline_list} | {default_pipeline} |\n"
    return table

def generate_output_formats_table():
    backend_formats = backend_factory.SigmAIQBackend.display_backends_and_outputs()
    table = "| Backend Option | Output Format Option | Description |\n|-----------------|------------------------|-------------|\n"
    for backend, data in backend_formats.items():
        output_formats = []
        descriptions = []
        for format, description in data['output_formats'].items():
            output_formats.append(format)
            descriptions.append(description)
        
        output_formats_str = "<br>".join(output_formats)
        descriptions_str = "<br>".join(descriptions)
        table += f"| {backend} | {output_formats_str} | {descriptions_str} |\n"
    return table

def generate_pipelines_table():
    pipelines = pipeline_factory.AVAILABLE_PIPELINES
    table = "| Pipeline Option | Description | Display Name |\n|------------------|-------------|---------------|\n"
    for pipeline, data in pipelines.items():
        description = data['description']
        display_name = data['display_name']
        table += f"| {pipeline} | {description} | {display_name} |\n"
    return table

def main():
    backends_table = generate_backends_table()
    output_formats_table = generate_output_formats_table()
    pipelines_table = generate_pipelines_table()

    print("## Available Backends\n")
    print(backends_table)
    print("\n## Backend Output Formats\n")
    print(output_formats_table)
    print("\n## Available Named Pipelines\n")
    print(pipelines_table)

if __name__ == "__main__":
    main()