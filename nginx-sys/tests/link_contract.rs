#[path = "../build/link.rs"]
mod link;

use link::{
    NativeLinkInput, logical_makefile_lines, nginx_binary_objects, nginx_build_archives,
    nginx_native_link_inputs,
};

#[test]
fn preserves_native_inputs_in_order_and_skips_nginx_target_artifacts() {
    let lines = logical_makefile_lines(
        "objs/nginx: objs/core.o objs/addon.a \\\n /vendor/libssl.a\n\n\t$(LINK) -o objs/nginx \\\n objs/core.o -L/vendor/lib -lpcre2-8 objs/addon.a \\\n /vendor/libssl.a /vendor/provider.o -Wl,--whole-archive /vendor/libcrypto.a \\\n -Wl,--no-whole-archive -pthread -Wl,-E\n",
    );

    assert_eq!(nginx_binary_objects(&lines), ["objs/core.o"]);
    assert_eq!(
        nginx_build_archives(
            &lines,
            std::path::Path::new("/workspace/nginx"),
            std::path::Path::new("/workspace/nginx/objs"),
        )
        .unwrap(),
        ["objs/addon.a"]
    );
    assert_eq!(
        nginx_native_link_inputs(&lines, &["objs/core.o".into(), "objs/addon.a".into()]).unwrap(),
        vec![
            NativeLinkInput::SearchPath("/vendor/lib".into()),
            NativeLinkInput::Library { name: "pcre2-8".into(), whole_archive: false },
            NativeLinkInput::Archive { path: "/vendor/libssl.a".into(), whole_archive: false },
            NativeLinkInput::Object("/vendor/provider.o".into()),
            NativeLinkInput::Archive { path: "/vendor/libcrypto.a".into(), whole_archive: true },
            NativeLinkInput::Library { name: "pthread".into(), whole_archive: false },
        ]
    );
}

#[test]
fn rejects_unknown_native_link_tokens() {
    let lines = logical_makefile_lines(
        "objs/nginx: objs/core.o\n\n\t$(LINK) -o objs/nginx objs/core.o --unknown-link-mode\n",
    );

    let error = nginx_native_link_inputs(&lines, &[]).unwrap_err();
    assert!(error.contains("--unknown-link-mode"), "{error}");
}
