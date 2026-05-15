use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Data, DeriveInput, Expr, Fields, Lit, Meta, MetaNameValue, Type, parse_macro_input,
    punctuated::Punctuated,
};

/// Derives a `completion_node()` method returning a `crate::completions::CompletionNode`.
///
/// Works on enums (subcommand-style) and structs (args-style):
/// - **Enum variants**: collects `#[command(name = "...")]` as subcommand names and
///   `#[arg(long = "...")]` fields as args per variant. Variants with a
///   `#[command(subcommand)]` field whose type also derives `Completions` will have their
///   completion tree nested automatically. Hidden variants (`#[command(hide = true)]`) and
///   unnamed positional fields are skipped. `#[command(flatten)]` fields are also skipped.
/// - **Structs**: collects `#[arg(long = "...")]` from named fields; positional and flatten
///   fields are skipped.
#[proc_macro_derive(Completions, attributes(command, arg, completion))]
pub fn derive_completions(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    match &input.data {
        Data::Enum(data) => derive_for_enum(name, &data.variants),
        Data::Struct(data) => derive_for_struct(name, &data.fields),
        Data::Union(_) => syn::Error::new_spanned(name, "Completions cannot be derived for unions")
            .to_compile_error()
            .into(),
    }
}

fn derive_for_enum(
    name: &syn::Ident,
    variants: &Punctuated<syn::Variant, syn::Token![,]>,
) -> TokenStream {
    let mut commands: Vec<String> = Vec::new();
    let mut local_fns: Vec<TokenStream2> = Vec::new();
    let mut subcommand_entries: Vec<TokenStream2> = Vec::new();

    for variant in variants {
        let (cmd_name, aliases, hidden) = parse_command_attrs(&variant.attrs);

        if hidden {
            continue;
        }

        let cmd_name = match cmd_name {
            Some(n) => n,
            None => continue,
        };

        commands.push(cmd_name.clone());

        let fn_ident = variant_fn_ident(&cmd_name);

        let fields = match &variant.fields {
            Fields::Named(f) => &f.named,
            Fields::Unnamed(_) | Fields::Unit => {
                local_fns.push(quote! {
                    fn #fn_ident() -> crate::completions::CompletionNode {
                        crate::completions::CompletionNode {
                            commands: vec![],
                            args: vec![],
                            subcommands: vec![],
                            values: None,
                        }
                    }
                });
                push_subcommand_entries(&mut subcommand_entries, &cmd_name, &aliases, &fn_ident);
                continue;
            }
        };

        let (variant_args, subcommand_ty, values_fn) = parse_fields(fields);

        let values_expr = match values_fn {
            Some(fn_ts) => quote! { Some(#fn_ts as fn(&str, &[String]) -> Vec<String>) },
            None => quote! { None },
        };

        let node_body = match subcommand_ty {
            Some(sub_ty) if variant_args.is_empty() => quote! {
                <#sub_ty>::completion_node()
            },
            Some(sub_ty) => quote! {
                {
                    let inner = <#sub_ty>::completion_node();
                    let mut merged = inner.args;
                    #(merged.push(#variant_args);)*
                    crate::completions::CompletionNode {
                        commands: inner.commands,
                        args: merged,
                        subcommands: inner.subcommands,
                        values: inner.values,
                    }
                }
            },
            None => quote! {
                crate::completions::CompletionNode {
                    commands: vec![],
                    args: vec![#(#variant_args),*],
                    subcommands: vec![],
                    values: #values_expr,
                }
            },
        };

        local_fns.push(quote! {
            fn #fn_ident() -> crate::completions::CompletionNode {
                #node_body
            }
        });

        push_subcommand_entries(&mut subcommand_entries, &cmd_name, &aliases, &fn_ident);
    }

    let expanded = quote! {
        impl #name {
            pub fn completion_node() -> crate::completions::CompletionNode {
                #(#local_fns)*
                crate::completions::CompletionNode {
                    commands: vec![#(#commands),*],
                    args: vec![],
                    subcommands: vec![#(#subcommand_entries),*],
                    values: None,
                }
            }
        }
    };

    expanded.into()
}

fn derive_for_struct(name: &syn::Ident, fields: &Fields) -> TokenStream {
    let named = match fields {
        Fields::Named(f) => &f.named,
        _ => {
            return syn::Error::new_spanned(name, "Completions on structs requires named fields")
                .to_compile_error()
                .into();
        }
    };

    let (args, _, values_fn) = parse_fields(named);

    let values_expr = match values_fn {
        Some(fn_ts) => quote! { Some(#fn_ts as fn(&str, &[String]) -> Vec<String>) },
        None => quote! { None },
    };

    let expanded = quote! {
        impl #name {
            pub fn completion_node() -> crate::completions::CompletionNode {
                crate::completions::CompletionNode {
                    commands: vec![],
                    args: vec![#(#args),*],
                    subcommands: vec![],
                    values: #values_expr,
                }
            }
        }
    };

    expanded.into()
}

/// Parses `#[command(...)]` attributes on a variant, returning `(name, aliases, is_hidden)`.
fn parse_command_attrs(attrs: &[syn::Attribute]) -> (Option<String>, Vec<String>, bool) {
    let mut cmd_name = None;
    let mut aliases: Vec<String> = Vec::new();
    let mut hidden = false;

    for attr in attrs {
        if !attr.path().is_ident("command") {
            continue;
        }
        let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
        else {
            continue;
        };
        for meta in &nested {
            match meta {
                Meta::NameValue(MetaNameValue {
                    path,
                    value:
                        Expr::Lit(syn::ExprLit {
                            lit: Lit::Str(s), ..
                        }),
                    ..
                }) if path.is_ident("name") => {
                    cmd_name = Some(s.value());
                }
                Meta::NameValue(MetaNameValue {
                    path,
                    value:
                        Expr::Lit(syn::ExprLit {
                            lit: Lit::Str(s), ..
                        }),
                    ..
                }) if path.is_ident("alias") => {
                    aliases.push(s.value());
                }
                Meta::NameValue(MetaNameValue {
                    path,
                    value:
                        Expr::Lit(syn::ExprLit {
                            lit: Lit::Bool(b), ..
                        }),
                    ..
                }) if path.is_ident("hide") && b.value => {
                    hidden = true;
                }
                _ => {}
            }
        }
    }

    (cmd_name, aliases, hidden)
}

/// Parses named fields, returning `(long_args, subcommand_type, values_fn)`.
///
/// - `#[arg(long = "foo")]` → `"--foo"` added to args
/// - `#[command(subcommand)]` → captures the field type as the subcommand delegate
/// - `#[completion(values = "fn_name")]` → captures the function path for dynamic completions
/// - Positional fields and `#[command(flatten)]` fields are skipped
fn parse_fields(
    fields: &Punctuated<syn::Field, syn::Token![,]>,
) -> (Vec<String>, Option<Type>, Option<TokenStream2>) {
    let mut args: Vec<String> = Vec::new();
    let mut subcommand_ty: Option<Type> = None;
    let mut values_fn: Option<TokenStream2> = None;

    for field in fields {
        let mut is_subcommand = false;
        let mut long_name: Option<String> = None;

        for attr in &field.attrs {
            if attr.path().is_ident("command") {
                let Ok(nested) =
                    attr.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
                else {
                    continue;
                };
                for meta in &nested {
                    if let Meta::Path(p) = meta {
                        if p.is_ident("subcommand") {
                            is_subcommand = true;
                        }
                    }
                }
            } else if attr.path().is_ident("arg") {
                let Ok(nested) =
                    attr.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
                else {
                    continue;
                };
                for meta in &nested {
                    if let Meta::NameValue(MetaNameValue {
                        path,
                        value:
                            Expr::Lit(syn::ExprLit {
                                lit: Lit::Str(s), ..
                            }),
                        ..
                    }) = meta
                    {
                        if path.is_ident("long") {
                            long_name = Some(format!("--{}", s.value()));
                        }
                    }
                }
            } else if attr.path().is_ident("completion") {
                let Ok(nested) =
                    attr.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
                else {
                    continue;
                };
                for meta in &nested {
                    if let Meta::NameValue(MetaNameValue {
                        path,
                        value:
                            Expr::Lit(syn::ExprLit {
                                lit: Lit::Str(s), ..
                            }),
                        ..
                    }) = meta
                    {
                        if path.is_ident("values") {
                            if let Ok(fn_path) = syn::parse_str::<syn::Path>(&s.value()) {
                                values_fn = Some(quote! { #fn_path });
                            }
                        }
                    }
                }
            }
        }

        if is_subcommand {
            subcommand_ty = Some(field.ty.clone());
        } else if let Some(long) = long_name {
            args.push(long);
        }
        // flatten, completion-only, and other positional fields are skipped for args
    }

    (args, subcommand_ty, values_fn)
}

/// Derives a sanitized local-function identifier from a command name.
fn variant_fn_ident(cmd_name: &str) -> proc_macro2::Ident {
    let sanitized = cmd_name.replace('-', "_").replace(' ', "_");
    proc_macro2::Ident::new(
        &format!("__completion_{sanitized}"),
        proc_macro2::Span::call_site(),
    )
}

/// Pushes one subcommand entry per canonical name + each alias, all pointing to the same fn.
fn push_subcommand_entries(
    entries: &mut Vec<TokenStream2>,
    cmd_name: &str,
    aliases: &[String],
    fn_ident: &proc_macro2::Ident,
) {
    entries.push(quote! {
        (#cmd_name, #fn_ident as fn() -> crate::completions::CompletionNode)
    });
    for alias in aliases {
        entries.push(quote! {
            (#alias, #fn_ident as fn() -> crate::completions::CompletionNode)
        });
    }
}
