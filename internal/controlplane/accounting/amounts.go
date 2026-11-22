package accounting

const (
	Chat       = "chat"
	Vision     = "vision"
	Embed      = "embed"
	Transcribe = "transcribe"
	OCR        = "ocr"
)

// Amounts is what one call reserves or settles, in its operation's units:
// tokens for chat and embed (an embedding has no output), seconds of audio
// for a transcription, pages for OCR.
type Amounts struct {
	Operation           string
	Input, Output       int64
	AudioSeconds, Pages int64
}

// maxUnits bounds a reported amount in any unit.
const maxUnits = 1e12

// Valid says whether the amounts fit their operation. A reservation must
// count something; a settlement may be zero.
func (q Amounts) Valid(reservation bool) bool {
	for _, v := range []int64{q.Input, q.Output, q.AudioSeconds, q.Pages} {
		if v < 0 || v > maxUnits {
			return false
		}
	}
	switch q.Operation {
	case Chat:
		return q.AudioSeconds == 0 && q.Pages == 0 && (!reservation || q.Input+q.Output >= 1)
	case Embed:
		return q.Output == 0 && q.AudioSeconds == 0 && q.Pages == 0 && (!reservation || q.Input >= 1)
	case Transcribe:
		return q.Input == 0 && q.Output == 0 && q.Pages == 0 && (!reservation || q.AudioSeconds >= 1)
	case OCR:
		return q.Input == 0 && q.Output == 0 && q.AudioSeconds == 0 && q.Pages <= 1e9 && (!reservation || q.Pages >= 1)
	}
	return false
}

// Tokens is what a token budget counts of the amounts: transcription and OCR
// count none.
func (q Amounts) Tokens() int64 { return q.Input + q.Output }

// Prices are an alias's prices as a call keeps them from its reservation.
// Priced says whether the call's own unit was priced.
type Prices struct {
	Priced                            bool
	InputPerMillion, OutputPerMillion int64 // per million tokens
	AudioPerMinute, PerPage           int64
}

// Cost is the estimated cost of the amounts in micro-units, rounded up once so
// that an estimate never under-reports; ok is false if it does not fit in an
// int64.
func (p Prices) Cost(q Amounts) (int64, bool) {
	switch q.Operation {
	case Transcribe:
		return unitCost(q.AudioSeconds, p.AudioPerMinute, 60)
	case OCR:
		return unitCost(q.Pages, p.PerPage, 1)
	}
	return tokenCost(q.Input, q.Output, p.InputPerMillion, p.OutputPerMillion)
}

// PricesFor reads the prices an operation's call keeps from its alias.
func PricesFor(op string, tokensPriced bool, input, output int64, audio, page *int64) Prices {
	p := Prices{Priced: tokensPriced, InputPerMillion: input, OutputPerMillion: output}
	if audio != nil {
		p.AudioPerMinute = *audio
	}
	if page != nil {
		p.PerPage = *page
	}
	switch op {
	case Transcribe:
		p.Priced = audio != nil
	case OCR:
		p.Priced = page != nil
	}
	return p
}
