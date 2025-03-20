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

def update_readme():
    # Read the current README
    with open("README.md", "r") as f:
        content = f.read()

    # Generate new tables
    backends_table = generate_backends_table()
    output_formats_table = generate_output_formats_table()
    pipelines_table = generate_pipelines_table()

    # Define the sections and their content
    sections = {
        "### Available Backends\n": backends_table,
        "### Backend Output Formats\n": output_formats_table,
        "### Available Named Pipelines\n": pipelines_table
    }

    # Replace each section
    for section_header, new_content in sections.items():
        # Find the section
        start = content.find(section_header)
        if start == -1:
            continue
        
        # Find the next section header or heading
        next_section = content.find("\n#", start + len(section_header))
        if next_section == -1:
            next_section = len(content)
        
        # Replace the content
        content = (
            content[:start] +
            section_header + "\n" +
            new_content + "\n" +
            content[next_section:]
        )

    # Write the updated content
    with open("README.md", "w") as f:
        f.write(content)

if __name__ == "__main__":
    update_readme()