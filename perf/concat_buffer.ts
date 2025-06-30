import { run, bench, lineplot, summary, do_not_optimize } from 'mitata';
import { randomBytes } from "crypto";

function manual(...buffers) {
    const totalLength = buffers.reduce((acc, buf) => acc + buf.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const buf of buffers) {
        result.set(buf, offset);
        offset += buf.length;
    }
    return result;
}

function concat(...buffers): Buffer {
    return Buffer.concat(buffers)
}

function uint8array(...buffers): Buffer {
    return buffers.reduce((acc, buf) => {
        const newArr = new Uint8Array(acc.length + buf.length);
        newArr.set(acc, 0);
        newArr.set(buf, acc.length);
        return newArr;
    }, new Uint8Array(0));
}

function reduce(...buffers) {
    return buffers.reduce((acc, buf) => {
        const newArr = new Uint8Array(acc.length + buf.length);
        newArr.set(acc, 0);
        newArr.set(buf, acc.length);
        return newArr;
    }, new Uint8Array(0));
}

const buf1 = randomBytes(64);
const buf2 = randomBytes(64);
const buf3 = randomBytes(64);
const buf4 = randomBytes(64);
const buf5 = randomBytes(64);

lineplot(()=> {
    summary(() => {
        
        bench('manual', function () {
            do_not_optimize(manual(buf1, buf2, buf3, buf4, buf5));
        });
        
        bench('concat()', function () {
            do_not_optimize(concat(buf1, buf2, buf3, buf4, buf5));
        });

        bench('Uint8Array', function () {
            do_not_optimize(uint8array(buf1, buf2, buf3, buf4, buf5));
        })

        bench('reduce()', function () {
            do_not_optimize(reduce(buf1, buf2, buf3, buf4, buf5));
        });
    })
})

run();