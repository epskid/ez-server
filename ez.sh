#!/bin/sh

subcommand=$1

show_help_message() {
    echo "\
ez.sh: super-minimal build system
available commands:
    help:
        show this message.
    build [profile]:
        builds the project.
        profile should be debug, release, or release-stripped. (leave empty for debug)
        outputs to ./target/
    run [profile]:
        builds and runs the project.
        profile should be debug, release, or release-stripped. (leave empty for debug)
        outputs to ./target/
    debug [profile]:
        creates a debug build and launches valgrind + gdb.
        can be any profile, but you should use ones with GDB-supported debug info: gdb, release-gdb
    clean:
        cleans all artifacts. (removes ./target/)"
}

if [ -n "$1" ]; then
    shift
else
    show_help_message
    exit
fi

case $subcommand in
    help)
        show_help_message
    ;;
    build)
        case $1 in
            ""|debug)
                set -- "-debug"
                extras="-gdwarf-4 -O0 -DEZ_DEBUG"
            ;;
            gdb)
                set -- "-gdb"
                extras="-ggdb -O0 -DEZ_DEBUG"
            ;;
            release)
                set -- "-release"
                extras="-O3 -DEZ_RELEASE"
            ;;
            release-gdb)
                set -- "-release-gdb"
                extras="-ggdb -O3 -DEZ_RELEASE"
            ;;
            release-stripped)
                set -- "-release-stripped"
                extras="-O3 -Wl,-s -DEZ_RELEASE -DEZ_STRIPPED"
            ;;
            *)
                echo "[ez.sh] invalid build profile: $1" > /dev/stderr
                exit 1
            ;;
        esac

        if [ ! -d "target" ]; then
            mkdir target
        fi

        output="./target/$( basename -- "$(dirname -- "$(readlink -f -- "$0")")" )$1"

        IFS=' ' clang $extras -std=gnu23 -Wpedantic -Wall -Werror src/main.c -o $output
        clang_result=$?

        if [ ! -t 1 ]; then
            echo -n $output
        fi

        exit $clang_result
    ;;
    run)
        output=$(./ez.sh build $1)

        if [ $? -eq 0 ]; then
            $output
        fi
    ;;
    debug)
        output=$(./ez.sh build "${1:-gdb}")
        
        if [ $? -eq 0 ]; then
            valgrind --vgdb=yes --vgdb-error=0 --leak-check=yes --tool=memcheck --num-callers=16 --leak-resolution=high --track-origins=yes $output &
            valgrind_pid=$!
            gdb -x gdbinit $output

            if [ -d "/proc/$valgrind_pid" ]; then
                kill -KILL $valgrind_pid
            fi
        fi
    ;;
    clean)
        rm -rf ./target
    ;;
    *)
        show_help_message
        echo "[ez.sh] not a command: $subcommand" > /dev/stderr
        exit 1
    ;;
esac
