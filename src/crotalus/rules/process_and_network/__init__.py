"""Rules about code that starts programs or uses the network, by when it runs.

    setup_py_install_time    setup.py, which runs when the package is installed
    import_time_code         modules that run when the package is imported
    unimported_script_code   modules nothing imports, which run only when run

They share rules/helpers/static_code_analysis.process_and_network_calls; the two
import rules also share rules/helpers/import_graph.
"""
