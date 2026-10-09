/** Explicit success or failure; expected failures never travel as exceptions. */
export type Result<T, E> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

/** Wrap a successful value. */
export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });

/** Wrap an expected failure. */
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
