///This takes two functions, and produces a function.
///
///The return function takes two arguments. On the first Argument, the first Function will get run.
///The second function gets run, if the first function returned a `Some` value.
///The second function receives the `Some(value)`, of the first Function, and the second Argument, of the return function.
///
///The return function returns the output, of the second Function, as a Some value, and None, if the first function produced None.
//todo: does this bring a performance benefit?
#[inline]
pub(crate) fn optpredicate<I, I2, IO, O>(
    fi: impl Fn(I) -> Option<IO>,
    o: impl Fn(IO, I2) -> O,
) -> impl Fn(I, I2) -> Option<O> {
    move |i, i2| fi(i).map(|io| o(io, i2))
}
///This swaps Function inputs, of a function f.
pub(crate) fn swap_fn_args<I, I2, O>(f: impl Fn(I, I2) -> O) -> impl Fn(I2, I) -> O {
    move |i, i2| f(i2, i)
}
///This takes 3 functions, and produces a forth.
///The Resulting function will take the input, of the first, and second supplied function.
///The 3rd function will take both outputs, of the first two functions, and return it, as the output, of the resulting function.
//Fuck this. This is feels, like type argument abuse.
//todo: does this bring a performance benefit?
#[inline]
pub(crate) fn prepredicate<I, I2, IO, I2O, O>(
    fi: impl Fn(I) -> IO,
    fi2: impl Fn(I2) -> I2O,
    o: impl Fn(IO, I2O) -> O,
) -> impl Fn(I, I2) -> O {
    move |i, i2| o(fi(i), fi2(i2))
}
