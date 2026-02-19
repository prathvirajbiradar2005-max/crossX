#!/usr/bin/env python3
"""
Test script to check if the demo button will work.
"""
import sys
import json

# Test if we can import everything needed
try:
    from utils.sample_data import generate_sample_csv
    print("✓ generate_sample_csv imported")
    
    # Try to generate sample data
    df = generate_sample_csv()
    print(f"✓ Sample CSV generated: {len(df)} transactions")
    print(f"  Columns: {df.columns.tolist()}")
    
    # Test if we can run the analysis pipeline
    from utils.validation import validate_csv
    from utils.graph_builder import build_transaction_graph, build_simple_digraph
    from detection.cycles import detect_cycles
    
    print("✓ All detection modules imported")
    
    is_valid, errors, cleaned_df = validate_csv(df)
    if not is_valid:
        print(f"✗ CSV validation failed: {errors}")
        sys.exit(1)
    print(f"✓ CSV validation passed: {len(cleaned_df)} rows")
    
    # Try building graphs
    G = build_transaction_graph(cleaned_df)
    simple_G = build_simple_digraph(G)
    print(f"✓ Graphs built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    
    # Try detecting cycles
    cycles = detect_cycles(simple_G)
    print(f"✓ Cycle detection complete: {len(cycles)} cycles detected")
    
    print("\n✅ ALL TESTS PASSED - Demo button should work!")
    
except Exception as e:
    import traceback
    print(f"\n❌ ERROR: {e}")
    traceback.print_exc()
    sys.exit(1)
