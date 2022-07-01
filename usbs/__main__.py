import argparse
import logging
from . import usbs

# project-global log configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level="DEBUG",
)

log = logging.getLogger(__name__)


def parse():
    parser = argparse.ArgumentParser(
        description="""Rewrite a binary so that the code is relocated. """
        """Running this script from the terminal does not allow any """
        """instrumentation. For that, use this as a library instead."""
    )
    parser.add_argument("filename", help="The executable file to rewrite.")
    parser.add_argument(
        "--arch",
        default="arm",
        help="The architecture of the binary.  Default is 'ARM'.",
    )
    return parser


if __name__ == "__main__":
    parser = parse()
    args = parser.parse_args()
    rewriter = usbs.Rewriter()
    rewriter.rewrite(args.filename, args.arch)
