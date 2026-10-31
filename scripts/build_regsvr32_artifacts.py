"""Build a new version of corrected Regsvr32 artifacts; preserve old consumers."""

from scripts.build_reviewed_slice_artifacts import main


if __name__ == "__main__":
    main("regsvr32-c2")
