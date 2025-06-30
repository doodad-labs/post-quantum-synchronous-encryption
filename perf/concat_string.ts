import { run, bench, lineplot, summary, do_not_optimize } from 'mitata';
import { randomBytes } from "crypto";

function join(str1, str2, str3): string {
    return [
        str1,
        str2,
        str3
    ].join('')
}

function template(str1, str2, str3): string {
    return `${str1}${str2}${str3}`;
}

function plus(str1, str2, str3): string {
    return str1 + str2 + str3;
}

function concat(str1, str2, str3): string {
    return str1.concat(str2, str3);
}

const str1 = randomBytes(64).toString('hex');
const str2 = randomBytes(64).toString('hex');
const str3 = randomBytes(64).toString('hex');

lineplot(()=> {
    summary(() => {
        bench('join', function () {
            do_not_optimize(join(str1, str2, str3));
        });

        bench('template', function () {
            do_not_optimize(template(str1, str2, str3));
        });

        bench('plus', function () {
            do_not_optimize(plus(str1, str2, str3));
        });

        bench('concat', function () {
            do_not_optimize(concat(str1, str2, str3));
        });
    })
})

run();