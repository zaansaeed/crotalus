"""Rules about code that starts programs or uses the network, by when it runs.

All three come from process_and_network_code.check:

    install_time_code        setup.py and the modules it imports, run by pip install
    import_time_code         the modules that run when the package is imported
    unimported_script_code   modules nothing imports, which run only when run

They find which files run when with rules/helpers/import_graph.
"""
