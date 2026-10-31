"""Build a new version of corrected PurpleSharp artifacts; preserve old consumers."""

from scripts.build_reviewed_slice_artifacts import main


if __name__ == "__main__":
    main("purplesharp-ad")
